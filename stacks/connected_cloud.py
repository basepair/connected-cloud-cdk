import os

from aws_cdk import (
    CfnParameter,
    CfnOutput,
    RemovalPolicy,
    Stack,
    aws_iam as iam,
    aws_s3 as s3,
    aws_omics as omics,
)
from constructs import Construct


class BasepairConnectedCloud(Stack):
    master_account_id = None
    master_role_name = None
    slave_account_id = os.getenv('CDK_DEFAULT_ACCOUNT')
    slave_account_region = os.getenv('CDK_DEFAULT_REGION')

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.master_account_id = CfnParameter(
            self,
            "MasterAccountId",
            type="String",
            default="613396392907",
            description="Master Account ID from Basepair",
        ).value_as_string

        self.master_role_name = CfnParameter(
            self,
            "MasterRoleName",
            type="String",
            default="Webapp-Prod01-NA-1-Prod",
            description="Master Account Role Name from Basepair",
        ).value_as_string

        # Create a s3 bucket for samples storage
        self.bucket = s3.Bucket(
            self,
            'webapp_bucket',
            access_control=s3.BucketAccessControl.BUCKET_OWNER_FULL_CONTROL,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            bucket_name=f"{self.slave_account_id}-basepair",
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
                "partner.basepair.omics.storage": self._get_omics_storage_policy(),
                "partner.basepair.omics.workflow": self._get_omics_workflow_policy(),
                "partner.basepair.s3": self._get_s3_policy()

            }
        )

        # Create a trusted role for the basepair to access resources in the partner account
        self.trusted_role = iam.Role(
            self,
            "BasepairTrustedRole",
            assumed_by=iam.ArnPrincipal(f"arn:aws:iam::{self.master_account_id}:role/{self.master_role_name}"),
            description="Basepair Trusted Role",
            role_name="partner.basepair.trusted",
            inline_policies={
                "partner.basepair.cw": self._get_cw_role_policy(),
                "partner.basepair.omics.storage": self._get_omics_storage_policy(),
                "partner.basepair.omics.workflow": self._get_omics_workflow_policy(),
                "partner.basepair.iam.assume.role": self._get_iam_assume_role_policy(),
                "partner.basepair.s3": self._get_s3_policy()
            }
        )

        CfnOutput(
            self,
            "TrustedRoleOutput",
            export_name="TrustedRoleARN",
            value=self.trusted_role.role_arn
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
                        "omics:GetReadSet",
                        "omics:GetReadSetExportJob",
                        "omics:GetReadSetImportJob",
                        "omics:GetReadSetMetadata",
                        "omics:GetReferenceImportJob",
                        "omics:ListReadSets",
                        "omics:StartReadSetExportJob",
                        "omics:StartReadSetImportJob",
                        "omics:StartReferenceImportJob",
                    ],
                    resources=[
                        f"arn:aws:omics:{self.slave_account_region}:{self.slave_account_id}:referenceStore/{self.reference_store.attr_reference_store_id}/reference/*",
                        f"arn:aws:omics:{self.slave_account_region}:{self.slave_account_id}:referenceStore/{self.reference_store.attr_reference_store_id}",
                        f"arn:aws:omics:{self.slave_account_region}:{self.slave_account_id}:sequenceStore/{self.sequence_store.attr_sequence_store_id}/readSet/*",
                        f"arn:aws:omics:{self.slave_account_region}:{self.slave_account_id}:sequenceStore/{self.sequence_store.attr_sequence_store_id}"
                    ]
                )
            ]
        )

    def _get_omics_workflow_policy(self):
        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=[
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
                        f"arn:aws:omics:{self.slave_account_region}:{self.slave_account_id}:run/*",
                        f"arn:aws:omics:{self.slave_account_region}:{self.slave_account_id}:task/*",
                        f"arn:aws:omics:{self.slave_account_region}:{self.slave_account_id}:workflow/*",
                        f"arn:aws:omics:{self.slave_account_region}::workflow/*"
                    ]
                )
            ]
        )

    def _get_iam_assume_role_policy(self):
        return iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    resources=[
                        f"arn:aws:iam::{self.slave_account_id}:role/partner.basepair.omics"
                    ],
                    effect=iam.Effect.ALLOW,
                    sid="IAMSetRoleToWorkers"
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
                    resources=[f"arn:aws:logs:{self.slave_account_region}:{self.slave_account_id}:log-group:*"],
                    effect=iam.Effect.ALLOW,
                    sid="AllowCWLogs",
                ),
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    resources=[f"arn:aws:logs:{self.slave_account_region}:{self.slave_account_id}:log-group:*:log-stream:*"],
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
