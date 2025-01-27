import os

from aws_cdk import (
    CfnParameter,
    CfnOutput,
    RemovalPolicy,
    Stack,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_omics as omics,
)
from constructs import Construct

VPC_CIDR = "10.0.0.0/16"
SUBNET_CIDR_MASK = 24


class BasepairConnectedCloud(Stack):
    bp_account_id = None
    bp_role_name = None
    aws_account_id = os.getenv('CDK_DEFAULT_ACCOUNT')
    aws_region = os.getenv('CDK_DEFAULT_REGION')

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        iam.CfnServiceLinkedRole(
            self,
            "SpotInstanceServiceLinkedRole",
            aws_service_name="spot.amazonaws.com",
            description="Service-linked role for EC2 Spot Instances"
        )

        self.bp_account_id = CfnParameter(
            self,
            "BasepairAccountId",
            type="String",
            default="613396392907",
            description="AWS Account ID from Basepair",
            allowed_values=["613396392907"]
        ).value_as_string

        self.bp_role_name = CfnParameter(
            self,
            "BasepairRoleName",
            type="String",
            default="Webapp-Prod01-NA-1-Prod",
            description="AWS Role Name from Basepair",
            allowed_values=["Webapp-Prod01-NA-1-Prod", "Webapp-Prod02-AP-1-Prod"]
        ).value_as_string

        # Create a VPC
        self.basepair_vpc = ec2.Vpc(
            self,
            "BasepairVPC",
            ip_addresses=ec2.IpAddresses.cidr(VPC_CIDR),
            max_azs=3,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=SUBNET_CIDR_MASK,
                )
            ]
        )

        # Create a Security Group
        self.basepair_sg = ec2.SecurityGroup(
            self,
            "BasepairSecurityGroup",
            vpc=self.basepair_vpc,
            allow_all_outbound=True,
            description="Basepair Security Group",
        )

        # Add ingress rules to allow SSH access from anywhere on port 58746
        self.basepair_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(58746),
            description="allow SSH access from anywhere",
        )

        # Create a Key Pair and save it in Secrets Manager
        self.worker_keypair = ec2.CfnKeyPair(
            self,
            "KeyPair",
            key_name="worker",
            key_type="rsa"
        )

        # Create a s3 bucket for samples storage
        self.bucket = s3.Bucket(
            self,
            'webapp_bucket',
            access_control=s3.BucketAccessControl.BUCKET_OWNER_FULL_CONTROL,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            bucket_name=f"{self.aws_account_id}-basepair",
            cors=[
                s3.CorsRule(
                    allowed_origins=["https://*.basepairtech.com"],
                    allowed_methods=[s3.HttpMethods.GET, s3.HttpMethods.HEAD, s3.HttpMethods.POST, s3.HttpMethods.PUT],
                    allowed_headers=['*'],
                    exposed_headers=['ETag', 'Content-Type', 'Content-Length'],
                    max_age=3000,
                )
            ],
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Create a Reference store in omics
        self.reference_store = omics.CfnReferenceStore(
            self,
            "BasepairReferenceStore",
            name="BasepairReferenceStore",
            description="Basepair Reference Store"
        )

        # Create a Sequence store in omics
        self.sequence_store = omics.CfnSequenceStore(
            self,
            "BasepairSequenceStore",
            name="BasepairSequenceStore",
            description="Basepair Sequence Store"
        )

        # Create Omics service role
        self.omics_role = iam.Role(
            self,
            "OmicsRole",
            assumed_by=iam.ServicePrincipal("omics.amazonaws.com"),
            description="Omics Service Role",
            role_name="partner.basepair.omics",
            inline_policies={
                "partner.basepair.cw": self._get_cw_role_policy(),
                "partner.basepair.omics": self._get_omics_storage_policy(),
                "partner.basepair.s3": self._get_s3_policy()
            }
        )

        # Create a trusted role for the basepair to access resources in the partner account
        self.trusted_role = iam.Role(
            self,
            "BasepairTrustedRole",
            assumed_by=iam.ArnPrincipal(f"arn:aws:iam::{self.bp_account_id}:role/{self.bp_role_name}"),
            description="Basepair Trusted Role",
            role_name="partner.basepair.trusted",
            inline_policies={
                "partner.basepair.cw": self._get_cw_role_policy(),
                "partner.basepair.ec2": self._get_ec2_assume_role_policy(),
                "partner.basepair.iam": self._get_iam_assume_role_policy(),
                "partner.basepair.omics": self._get_omics_storage_policy(),
                "partner.basepair.s3": self._get_s3_policy()
            }
        )

        # Create a worker role for the ec2 instances
        self.worker_role = iam.Role(
            self,
            "BasepairWorkerRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Basepair Worker Role",
            role_name="partner.basepair.worker",
            inline_policies={
                "basepair.ecr": self._get_basepair_ecr_policy(),
                "partner.basepair.s3": self._get_s3_policy()
            }
        )

        instance_profile = iam.InstanceProfile(
            self,
            "InstanceProfile",
            instance_profile_name="partner.basepair.worker",
            role = self.worker_role,
        )

        CfnOutput(
            self,
            "Subnet1Output",
            export_name="Subnet1",
            value=self.basepair_vpc.public_subnets[0].subnet_id
        )
        CfnOutput(
            self,
            "Subnet2Output",
            export_name="Subnet2",
            value=self.basepair_vpc.public_subnets[1].subnet_id
        )
        CfnOutput(
            self,
            "Subnet3Output",
            export_name="Subnet3",
            value=self.basepair_vpc.public_subnets[2].subnet_id
        )
        CfnOutput(
            self,
            "SecurityGroupOutput",
            export_name="SecurityGroup",
            value=self.basepair_sg.security_group_id
        )

        CfnOutput(
            self,
            "TrustedRoleOutput",
            export_name="TrustedRoleARN",
            value=self.trusted_role.role_arn
        )

        CfnOutput(
            self,
            "WorkerRoleOutput",
            export_name="WorkerRoleARN",
            value=self.worker_role.role_arn
        )

        CfnOutput(
            self,
            "OmicsRoleOutput",
            export_name="OmicsRoleARN",
            value=self.omics_role.role_arn
        )

        CfnOutput(
            self,
            "BucketOutput",
            export_name="BucketName",
            value=self.bucket.bucket_name
        )

        CfnOutput(
            self,
            "SequenceStoreOutput",
            export_name="SequenceStoreId",
            value=self.sequence_store.attr_sequence_store_id
        )

        CfnOutput(
            self,
            "ReferenceStoreOutput",
            export_name="ReferenceStoreId",
            value=self.reference_store.attr_reference_store_id
        )

    def _get_s3_policy(self):
        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:GetObjectTagging",
                        "s3:ListBucket",
                        "s3:ListMultipartUploadParts",
                        "s3:PutObject",
                        "s3:PutObjectTagging",
                    ],
                    resources=[
                        f"arn:aws:s3:::{self.bucket.bucket_name}",
                        f"arn:aws:s3:::{self.bucket.bucket_name}/*"
                    ],
                    effect=iam.Effect.ALLOW,
                    sid="AllowS3"
                )
            ]
        )

    def _get_omics_storage_policy(self):
        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "omics:BatchDeleteReadSet",
                        "omics:DeleteReference",
                        "omics:GetReadSet",
                        "omics:GetReadSetExportJob",
                        "omics:GetReadSetImportJob",
                        "omics:GetReadSetMetadata",
                        "omics:GetReferenceImportJob",
                        "omics:GetReferenceMetadata",
                        "omics:ListReadSets",
                        "omics:ListReferences",
                        "omics:StartReadSetActivationJob",
                        "omics:StartReadSetExportJob",
                        "omics:StartReadSetImportJob",
                        "omics:StartReferenceImportJob",
                    ],
                    resources=[
                        f"arn:aws:omics:{self.aws_region}:{self.aws_account_id}:referenceStore/{self.reference_store.attr_reference_store_id}/reference/*",
                        f"arn:aws:omics:{self.aws_region}:{self.aws_account_id}:referenceStore/{self.reference_store.attr_reference_store_id}",
                        f"arn:aws:omics:{self.aws_region}:{self.aws_account_id}:sequenceStore/{self.sequence_store.attr_sequence_store_id}/readSet/*",
                        f"arn:aws:omics:{self.aws_region}:{self.aws_account_id}:sequenceStore/{self.sequence_store.attr_sequence_store_id}"
                    ],
                    effect=iam.Effect.ALLOW,
                    sid="AllowOmicsStorage"
                ),
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject",
                        "s3:ListBucket"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=['*'],
                    sid="HealthOmicsS3URIs",
                    conditions={
                        "StringLike": {
                            "s3:DataAccessPointArn": f"arn:aws:s3:{self.aws_region}:*"
                        }
                    },
                ),
                iam.PolicyStatement(
                    actions=["kms:Decrypt"],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:kms:{self.aws_region}:*:*"],
                    sid="HealthOmicsKMSKey",
                ),
                iam.PolicyStatement(
                    actions=[
                        "omics:CancelRun",
                        "omics:CreateWorkflow",
                        "omics:DeleteRun",
                        "omics:DeleteWorkflow",
                        "omics:GetRun",
                        "omics:GetRunTask",
                        "omics:GetWorkflow",
                        "omics:ListRunTasks",
                        "omics:ListWorkflows",
                        "omics:StartRun",
                    ],
                    resources=[
                        f"arn:aws:omics:{self.aws_region}:{self.aws_account_id}:run/*",
                        f"arn:aws:omics:{self.aws_region}:{self.aws_account_id}:task/*",
                        f"arn:aws:omics:{self.aws_region}:{self.aws_account_id}:workflow/*",
                        f"arn:aws:omics:{self.aws_region}::workflow/*"
                    ],
                    effect=iam.Effect.ALLOW,
                    sid="AllowOmicsWorkflow"
                ),
            ]
        )

    def _get_basepair_ecr_policy(self):
        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:GetRepositoryPolicy",
                        "ecr:DescribeRepositories",
                        "ecr:ListImages",
                        "ecr:DescribeImages",
                        "ecr:BatchGetImage",
                        "ecr:GetLifecyclePolicy",
                        "ecr:GetLifecyclePolicyPreview",
                        "ecr:ListTagsForResource",
                        "ecr:DescribeImageScanFindings"
                    ],
                    resources=[f"arn:aws:ecr:*:{self.bp_account_id}:repository/bio-*"],
                    conditions={"StringEquals": {"aws:ResourceTag/Type": "Bio"}},
                    effect=iam.Effect.ALLOW,
                    sid="AllowECRPullBioImage"
                )
            ]
        )

    def _get_iam_assume_role_policy(self):
        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    resources=[
                        f"arn:aws:iam::{self.aws_account_id}:role/partner.basepair.worker",
                        f"arn:aws:iam::{self.aws_account_id}:role/partner.basepair.omics"
                    ],
                    effect=iam.Effect.ALLOW,
                    sid="IAMSetRoleToWorkers"
                )
            ]
        )

    def _get_ec2_assume_role_policy(self):
        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "ec2:TerminateInstances",
                        "ec2:StartInstances",
                        "ec2:CreateTags",
                        "ec2:RunInstances",
                        "ec2:StopInstances"
                    ],
                    resources=[
                        "arn:aws:ec2:*:*:transit-gateway-route-table/*",
                        "arn:aws:ec2:*:*:client-vpn-endpoint/*",
                        "arn:aws:ec2:*::snapshot/*",
                        "arn:aws:ec2:*:*:network-interface/*",
                        "arn:aws:ec2:*:*:capacity-reservation/*",
                        "arn:aws:ec2:*:*:traffic-mirror-target/*",
                        "arn:aws:ec2:*:*:route-table/*",
                        "arn:aws:ec2:*:*:dedicated-host/*",
                        "arn:aws:ec2:*:*:key-pair/*",
                        "arn:aws:ec2:*:*:instance/*",
                        "arn:aws:ec2:*:*:transit-gateway-multicast-domain/*",
                        "arn:aws:ec2:*:*:elastic-gpu/*",
                        "arn:aws:ec2:*:*:local-gateway-route-table-virtual-interface-group-association/*",
                        "arn:aws:ec2:*:*:vpc-flow-log/*",
                        "arn:aws:ec2:*:*:vpc/*",
                        "arn:aws:ec2:*::image/*",
                        "arn:aws:ec2:*:*:vpc-endpoint-service/*",
                        "arn:aws:ec2:*:*:subnet/*",
                        "arn:aws:ec2:*:*:vpn-gateway/*",
                        "arn:aws:ec2:*:*:reserved-instances/*",
                        "arn:aws:ec2:*:*:vpn-connection/*",
                        "arn:aws:ec2:*:*:local-gateway-route-table-vpc-association/*",
                        "arn:aws:ec2:*:*:launch-template/*",
                        "arn:aws:ec2:*:*:traffic-mirror-session/*",
                        "arn:aws:ec2:*:*:security-group/*",
                        "arn:aws:ec2:*:*:network-acl/*",
                        "arn:aws:ec2:*:*:local-gateway/*",
                        "arn:aws:ec2:*:*:placement-group/*",
                        "arn:aws:ec2:*:*:internet-gateway/*",
                        "arn:aws:ec2:*:*:vpc-endpoint/*",
                        "arn:aws:ec2:*:*:spot-instances-request/*",
                        "arn:aws:ec2:*:*:local-gateway-route-table/*",
                        "arn:aws:ec2:*:*:local-gateway-virtual-interface-group/*",
                        "arn:aws:ec2:*:*:dhcp-options/*",
                        "arn:aws:elastic-inference:*:*:elastic-inference-accelerator/*",
                        "arn:aws:ec2:*:*:traffic-mirror-filter/*",
                        "arn:aws:ec2:*:*:local-gateway-virtual-interface/*",
                        "arn:aws:ec2:*:*:transit-gateway/*",
                        "arn:aws:ec2:*:*:volume/*",
                        "arn:aws:ec2:*::fpga-image/*",
                        "arn:aws:ec2:*:*:transit-gateway-attachment/*"
                    ],
                    effect=iam.Effect.ALLOW,
                ),
                iam.PolicyStatement(
                    actions=[
                        "ec2:DescribeSpotPriceHistory",
                        "ec2:CancelSpotInstanceRequests",
                        "ec2:DescribeInstances",
                        "ec2:RequestSpotInstances",
                        "ec2:DescribeTags",
                        "ec2:RunScheduledInstances",
                        "ec2:DescribeInstanceTypes",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSpotInstanceRequests",
                        "ec2:DescribeInstanceStatus",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeImages",
                    ],
                    resources=["*"],
                    effect=iam.Effect.ALLOW,
                )
            ]
        )

    def _get_cw_role_policy(self):
        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "logs:DescribeLogStreams",
                        "logs:CreateLogGroup"
                    ],
                    resources=[f"arn:aws:logs:{self.aws_region}:{self.aws_account_id}:log-group:*"],
                    effect=iam.Effect.ALLOW,
                    sid="AllowCWLogs",
                ),
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    resources=[
                        f"arn:aws:logs:{self.aws_region}:{self.aws_account_id}:log-group:*:log-stream:*"],
                    effect=iam.Effect.ALLOW,
                    sid="AllowCWLogsStream",
                ),
                iam.PolicyStatement(
                    actions=["cloudwatch:GetMetricStatistics"],
                    resources=["*"],
                    effect=iam.Effect.ALLOW,
                    sid="AllowCW",
                )
            ]
        )
