#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

"""Test functions for local resource policy evaluation (S3 bucket policies, IAM Role Trust Docs, etc.)"""

import logging
import unittest

from tests.build_test_graphs import *
from tests.build_test_graphs import _build_user_with_policy

from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult, \
    _statement_matches_action, UnsupportedConditionOperatorError
from principalmapper.querying.query_interface import local_check_authorization_full


class LocalResourcePolicyEvalTests(unittest.TestCase):
    def test_iam_assume_role(self):
        """Test that we are correctly validating policies for calls to `sts:AssumeRole`"""
        trust_doc_1 = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::000000000000:root'
                },
                'Action': 'sts:AssumeRole'
            }]
        }

        trust_doc_2 = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::999999999999:root'
                },
                'Action': 'sts:AssumeRole'
            }]
        }

        iam_user_1 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 'sts:AssumeRole',
                    'Resource': '*'
                }]
            },
            'single_user_policy',
            'asdf1',
            '1'
        )

        iam_user_2 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 's3:GetObject',
                    'Resource': '*'
                }]
            },
            'single_user_policy',
            'asdf2',
            '2'
        )

        # account root + iam policy => authorized
        self.assertTrue(
            local_check_authorization_full(
                iam_user_1,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_1,
                '000000000000'
            )
        )

        # iam policy only => not authorized
        self.assertFalse(
            local_check_authorization_full(
                iam_user_1,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_2,
                '000000000000'
            )
        )

        # account root only => not authorized
        self.assertFalse(
            local_check_authorization_full(
                iam_user_2,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_1,
                '000000000000'
            )
        )

        # Neither the account root nor the iam policy => not authorized
        self.assertFalse(
            local_check_authorization_full(
                iam_user_2,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_2,
                '000000000000'
            )
        )

        # A user from another account
        other_account_node = Node(
            'arn:aws:iam::999999999999:role/test_other',
            'ARIA00',
            [
                Policy(
                    'arn:aws:iam::999999999999:role/test_other',
                    'inline1',
                    {
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': 'sts:AssumeRole',
                            'Resource': '*'
                        }]
                    }
                )
            ],
            [],
            {},
            [],
            0,
            False,
            False,
            None,
            False,
            None
        )
        self.assertFalse(
            local_check_authorization_full(
                other_account_node,
                'sts:AssumeRole',
                'arn:aws:iam::000000000000:role/test1',
                {},
                trust_doc_1,
                '000000000000'
            )
        )

    def test_match_action_resource_policy_elements(self):
        """Test if we're correctly testing Action/Resource elements in resource policies"""
        bucket_policy_1 = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::bucket/object'
            }]
        }

        bucket_policy_2 = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::bucket/object'
            }]
        }

        iam_user_1 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 's3:GetObject',
                    'Resource': 'arn:aws:s3:::bucket/object'
                }]
            },
            'single_user_policy',
            'asdf1',
            '1'
        )

        iam_user_2 = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': 's3:GetObject',
                    'Resource': 'arn:aws:s3:::bucket/object'
                }]
            },
            'single_user_policy',
            'asdf2',
            '2'
        )

        rpa_result = resource_policy_authorization(
            iam_user_1,
            '000000000000',
            bucket_policy_1,
            's3:GetObject',
            'arn:aws:s3:::bucket/object',
            {}
        )
        self.assertTrue(
            rpa_result == ResourcePolicyEvalResult.NODE_MATCH
        )

        rpa_result = resource_policy_authorization(
            iam_user_1,
            '000000000000',
            bucket_policy_1,
            's3:PutObject',
            'arn:aws:s3:::bucket/object',
            {}
        )
        self.assertTrue(
            rpa_result == ResourcePolicyEvalResult.NO_MATCH
        )

    def test_sns_sqs_alternate_action_matching(self):
        """Test that we handle SNS:... and SQS:... differently with respect to action matching"""
        self.assertTrue(_statement_matches_action(
            {
                'Effect': 'Allow',
                'Action': 'SQS:CreateQueue',
                'Resource': '*'
            },
            'sqs:CreateQueue',
            {},
            True
        ))
        self.assertTrue(_statement_matches_action(
            {
                'Effect': 'Allow',
                'Action': 'SNS:CreateTopic',
                'Resource': '*'
            },
            'sns:CreateTopic',
            {},
            True
        ))
        self.assertFalse(_statement_matches_action(
            {
                'Effect': 'Allow',
                'Action': 'S3:CreateBucket',
                'Resource': '*'
            },
            's3:CreateTopic',
            {},
            True
        ))

    def test_sns_sqs_action_does_not_match_unrelated_actions(self):
        """Regression test: an SNS/SQS resource-policy action must only match SNS/SQS actions, not arbitrary actions.

        The action segment of the policy's action has to be normalized separately from the requested action; using
        the requested action for both sides caused every action to be treated as a match.
        """
        publish_statement = {
            'Effect': 'Allow',
            'Action': 'SNS:Publish',
            'Resource': '*'
        }
        # Only the matching SNS action hits
        self.assertTrue(_statement_matches_action(publish_statement, 'sns:Publish', {}, True))
        self.assertFalse(_statement_matches_action(publish_statement, 'sns:Subscribe', {}, True))
        # Unrelated services must not match
        self.assertFalse(_statement_matches_action(publish_statement, 's3:GetObject', {}, True))
        self.assertFalse(_statement_matches_action(publish_statement, 'sqs:SendMessage', {}, True))
        self.assertFalse(_statement_matches_action(publish_statement, 'ec2:RunInstances', {}, True))

        # Wildcards still match within the SNS/SQS service
        wildcard_statement = {
            'Effect': 'Allow',
            'Action': 'SNS:*',
            'Resource': '*'
        }
        self.assertTrue(_statement_matches_action(wildcard_statement, 'sns:Subscribe', {}, True))
        self.assertFalse(_statement_matches_action(wildcard_statement, 's3:GetObject', {}, True))

    def test_sns_sqs_notaction_does_not_match_unrelated_actions(self):
        """Regression test for the same normalization bug on the NotAction branch."""
        not_publish_statement = {
            'Effect': 'Allow',
            'NotAction': 'SNS:Publish',
            'Resource': '*'
        }
        # NotAction excludes sns:Publish only; unrelated actions remain allowed
        self.assertFalse(_statement_matches_action(not_publish_statement, 'sns:Publish', {}, True))
        self.assertTrue(_statement_matches_action(not_publish_statement, 's3:GetObject', {}, True))
        self.assertTrue(_statement_matches_action(not_publish_statement, 'sns:Subscribe', {}, True))

    def test_sns_sqs_resource_policy_authorization_is_scoped(self):
        """End-to-end regression: a topic policy granting SNS:Publish must not authorize an unrelated action."""
        iam_user = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            },
            'single_user_policy',
            'asdf1',
            '1'
        )
        topic_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 'SNS:Publish',
                'Resource': 'arn:aws:sns:us-east-1:000000000000:topic'
            }]
        }
        topic_arn = 'arn:aws:sns:us-east-1:000000000000:topic'

        self.assertEqual(
            resource_policy_authorization(iam_user, '000000000000', topic_policy, 'sns:Publish', topic_arn, {}),
            ResourcePolicyEvalResult.NODE_MATCH
        )
        self.assertEqual(
            resource_policy_authorization(iam_user, '000000000000', topic_policy, 's3:GetObject', topic_arn, {}),
            ResourcePolicyEvalResult.NO_MATCH
        )

    def test_unsupported_condition_operator_fails_closed(self):
        """An unrecognized condition operator must raise instead of being silently ignored (which would inflate an
        Allow statement's match set)."""
        iam_user = _build_user_with_policy(
            {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            },
            'single_user_policy',
            'asdf1',
            '1'
        )
        policy_with_unknown_operator = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 's3:GetObject',
                'Resource': 'arn:aws:s3:::bucket/object',
                'Condition': {
                    'BogusOperator': {'aws:username': 'asdf1'}
                }
            }]
        }
        with self.assertRaises(UnsupportedConditionOperatorError):
            resource_policy_authorization(
                iam_user,
                '000000000000',
                policy_with_unknown_operator,
                's3:GetObject',
                'arn:aws:s3:::bucket/object',
                {'aws:username': 'asdf1'}
            )

        qualified_unknown_operator = {
            'ForAllValues:BogusOperator': {'aws:username': 'asdf1'}
        }
        with self.assertRaises(UnsupportedConditionOperatorError):
            resource_policy_authorization(
                iam_user,
                '000000000000',
                {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': '*',
                        'Action': 's3:GetObject',
                        'Resource': 'arn:aws:s3:::bucket/object',
                        'Condition': qualified_unknown_operator
                    }]
                },
                's3:GetObject',
                'arn:aws:s3:::bucket/object',
                {'aws:username': 'asdf1'}
            )
