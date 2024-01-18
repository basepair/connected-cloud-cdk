#!/usr/bin/env python3
import os

import aws_cdk as cdk

from stacks import BasepairConnectedCloud

assert os.getenv('CDK_DEFAULT_ACCOUNT') is not None, "CDK_DEFAULT_ACCOUNT is not set in environment variables"
assert os.getenv('CDK_DEFAULT_REGION') is not None, "CDK_DEFAULT_REGION is not set in environment variables"

app = cdk.App()
stack = BasepairConnectedCloud(
    app,
    "BasepairConnectedCloud",
    termination_protection=True,
    stack_name="BasepairConnectedCloud",
    env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))
)

cdk.Tags.of(stack).add('created-by', 'cdk')
cdk.Tags.of(stack).add('project', 'basepair')
cdk.Tags.of(stack).add('env', 'prod')

app.synth()
