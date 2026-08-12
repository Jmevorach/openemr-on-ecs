"""Stable asset definitions shared by infrastructure components."""

from aws_cdk import IgnoreMode
from aws_cdk import aws_lambda as _lambda


def python_lambda_code() -> _lambda.AssetCode:
    """Package tracked Lambda source without local caches or documentation."""

    return _lambda.Code.from_asset(
        "lambda",
        exclude=[
            "README.md",
            "__pycache__/",
            "*.py[cod]",
            ".DS_Store",
            "Thumbs.db",
            "desktop.ini",
            ".*.sw?",
            "*~",
        ],
        ignore_mode=IgnoreMode.GIT,
    )
