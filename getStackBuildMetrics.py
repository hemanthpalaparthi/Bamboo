#!/usr/bin/env python

import json
import subprocess
import argparse
import logging
import boto3
import botocore
import datetime
import time
import os.path


def get_args():
    parser = argparse.ArgumentParser(
        description='Creates metadata & metrics for Radar',
        epilog='IMPORTANT: In case your CloudFormation stack is in another AWS account you need to provide the AWS assumeRole for STS to query the created stack. To upload RADAR metadata to S3 the default credentials or instance profile is used'
    )
    parser.add_argument('-s', '--stackname', required=True,
                        help='Name of the previously created stack.')
    parser.add_argument('-n', '--build-number', required=True,
                        help='$BUILD_NUMBER in Jenkins. Becomes JobName in radar (dont ask...)')
    parser.add_argument('-p', '--project-name',
                        help='$JOB_NAME. The project name that should be shown in radar. Static value')
    parser.add_argument('--pipeline-name', default="Daily Auto Testing",
                        help='Name of this pipeline. Static value. Currently not used in Radar. More a comment/description.')
    parser.add_argument('-b', '--bucket', required=True,
                        help='Bucket where the build metrics are stored')
    parser.add_argument('-c', '--customer-name', default="REAN",
                        help='Customer name')
    parser.add_argument('-e', '--endpoint-variable-name', default="TwoTierURL",
                        help='variable of endpoint given out by the CFT output')
    parser.add_argument('-a', '--assume-role',
                        help='The AWS sts role to assume. Only required if the Stack is in another AWS account as the S3 radar metadata')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()


def assumeRole(assume_role):
    try:
        client = boto3.client('sts')
        role_session = client.assume_role(RoleArn=assume_role,
                                          RoleSessionName='stack-build-metrics-' + str(int(time.time())))
    except ValueError:
        logging.critical('Unable to assume role: %s ', assume_role)

    return {'AccessKeyId': role_session['Credentials']['AccessKeyId'],
            'SecretAccessKey': role_session['Credentials']['SecretAccessKey'],
            'SessionToken': role_session['Credentials']['SessionToken']}


def stackoutputs(args, cf_client):
    '''
    # scripts/stack_outputs.py metrics-wordpress-provision "$StackName"
    '''
    stackname = args.stackname
    outdic = {}

    response = cf_client.describe_stacks(StackName=stackname)['Stacks'][0]
    if 'Outputs' in response:
        for i in response['Outputs']:
            outdic[i["OutputKey"]] = i["OutputValue"]
        logging.debug('outdic:\n%s', json.dumps(outdic, indent=4))
    else:
        logging.warn("No Outputs found in stack creation output")

    return json.dumps(outdic, indent=4)


def endPointTesting(args, stackData):
    '''
    Test the response time of the endpoint
    If no endpoint is found a empty response is returned
    script/2-tier.py
    '''
    outdic = {}
    StartTime = datetime.datetime.utcnow()
    testReturn = {}
    _stackData = json.loads(stackData)

    if args.endpoint_variable_name in _stackData:
        endPoint = _stackData[args.endpoint_variable_name]
        # TODO: we need to fix the curl. As soon as we hit HTTP/2 there is no more "OK"
        testReturn = subprocess.Popen("curl -I -s -L -k --retry 5 " + endPoint + "|grep -A 555 'OK'|head -1", shell=True, stdout=subprocess.PIPE).stdout.read().split()
    else:
        logging.warn("Provided endpoint %s doesn't exist in stack output", args.endpoint_variable_name)
        return json.dumps(outdic, indent=4)

    if len(testReturn) >= 2 and testReturn[2] == 'OK':
        outdic["EndpointTestingStatus"] = "Success"
    else:
        logging.warn("Test output: %s", testReturn)
        outdic["EndpointTestingStatus"] = "Failure"

    outdic["EndpointTestingStartTime"] = str(StartTime)
    EndTime = datetime.datetime.utcnow()
    outdic["EndpointTestingEndTime"] = str(EndTime)
    Duration = (EndTime) - (StartTime)
    outdic["EndpointTestingDuration"] = str(Duration)

    return json.dumps(outdic, indent=4)


def stackData(args, endPointTestingTime, cf_client):
    """
    Get stack output & its metrics
    ./automation-td/stack_launch/outputs.py "$StackName" "$StackName"
    Also includes logic of logs_on_failure.py
    """
    stackname = args.stackname
    outdic = {}
    StartTime = ''
    EndTime = ''
    # TODO: we don't need to query the stack all that time.
    response = cf_client.describe_stack_events(StackName=stackname)['StackEvents']
    length = len(response)
    outdic["StackId"] = response[0]['StackId']
    StartTime = cf_client.describe_stacks(StackName=stackname)['Stacks'][0]['CreationTime']
    outdic["StackCreationStartTime"] = str(StartTime)

    for i in range(length):
        if response[i]['LogicalResourceId'] == stackname:
            # There can be only one CREATE_COMPLETE and stack is done after
            if response[i]['ResourceStatus'] == "CREATE_COMPLETE":
                EndTime = response[i]['Timestamp']
                outdic["StackCreationEndTime"] = str(EndTime)
                outdic["StackCreationStatus"] = "Success"
                break
            # There can be only one ROLLBACK_COMPLETE and stack is done after
            if response[i]['ResourceStatus'] == "CREATE_COMPLETE":
                EndTime = response[i]['Timestamp']
                outdic["StackCreationEndTime"] = str(EndTime)
                outdic["StackCreationStatus"] = "Failure"
                break
            # There can be multiplebut multiple CREATE_FAILED
            if response[i]['ResourceStatus'] == "CREATE_FAILED":
                if EndTime == '':
                    EndTime = response[i]['Timestamp']
                elif EndTime > response[i]['Timestamp']:
                    EndTime = response[i]['Timestamp']
                outdic["StackCreationEndTime"] = str(EndTime)
                outdic["StackCreationStatus"] = "Failure"
            # TODO: We don't see here if we updated the stack, we need to
            # test that, too

    Duration = (EndTime) - (StartTime)
    outdic["StackCreationDuration"] = str(Duration)

    if 'EndpointTestingDuration' in outdic:
        metrics = json.loads(endPointTestingTime)
        outdic['EndpointTestingDuration'] = metrics['EndpointTestingDuration']
        outdic['EndpointTestingEndTime'] = metrics['EndpointTestingEndTime']
        outdic['EndpointTestingStartTime'] = metrics['EndpointTestingStartTime']
        outdic['EndpointTestingStatus'] = metrics['EndpointTestingStatus']

    return json.dumps(outdic, indent=4)


def combineMetrics(jenkinsData, stackMetricsData):
    """
    stack_launch/merge_json.py "$StackName.json" metrics-wordpress-provision.json
    """
    outdict = {}
    jenkins_outputs = json.loads(jenkinsData)
    stack_outputs = json.loads(stackMetricsData)
    data = {"StackOutputs": stack_outputs}
    outdict = dict(data.items() + jenkins_outputs.items())
    logging.debug('combineMetrics result:\n%s', json.dumps(outdict, indent=4))
    return json.dumps(outdict)


def reformat_json(args, elk_outputs):
    '''
    stack_launch/reformat_json.py "$JOB_NAME" "$BUILD_NUMBER" "$S3BuildMetricsBucket"

    We can probably optimize this function much more since we control
    in this script all previous created metadata that is checked here
    '''
    elk_data = json.loads(elk_outputs)
    stack_data = {}
    test_data = {}
    output_data = {}
    job_data = {}
    subdirs = []

    project_name = args.project_name
    build_number = args.build_number
    bucket = args.bucket

    client = boto3.client('s3')
    s3 = boto3.resource('s3')

    # Check if folder/bucket exists
    exists = False
    try:
        s3.Object(bucket, project_name + "/").load()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            logging.warn("Bucket / Folder doesn't exists: s3://%s/%s/", bucket, project_name)
            exists = False
        else:
            raise
    else:
        exists = True

    # Get all objects in bucket in folder level
    if exists:
        response = client.list_objects(
            Bucket=bucket,
            Delimiter="/",
            MaxKeys=2000,
            Prefix=project_name + "/"
        )
        if "CommonPrefixes" in response:
            subdirs = [x["Prefix"].replace(project_name, '').replace('/', '') for x in response["CommonPrefixes"]]
            subdirs = [int(s) for s in subdirs]
            subdirs = sorted(subdirs)
            subdirs = [str(s) for s in subdirs]

    if build_number not in subdirs:
        subdirs = subdirs + [build_number]

    stack_data["ProjectName"] = args.project_name
    stack_data["Type"] = "StackCreation"
    stack_data["CustomerName"] = args.customer_name
    stack_data["PipelineName"] = args.pipeline_name
    # yes, JobName = build_number, that is rediculous bad
    stack_data["JobName"] = build_number
    stack_data["PipelineId"] = project_name + "-" + build_number

    job_data["CustomerName"] = stack_data["CustomerName"]
    job_data["ProjectName"] = stack_data["ProjectName"]
    job_data["PipelineId"] = stack_data["PipelineId"]
    job_data["JobName"] = stack_data["JobName"]
    job_data["PipelineName"] = stack_data["PipelineName"]
    job_data["Type"] = "JobStatus"
    job_data["StartTime"] = datetime.datetime.utcnow().isoformat() + "+00:00"

    if "StackCreationStartTime" in elk_data:
        stack_data["StartTime"] = iso_dt(elk_data["StackCreationStartTime"])

    if "StackCreationEndTime" in elk_data:
        stack_data["EndTime"] = iso_dt(elk_data["StackCreationEndTime"])

    if "StackCreationDuration" in elk_data:
        stack_data["Duration"] = to_mins(elk_data["StackCreationDuration"])

    if "StackCreationStatus" in elk_data:
        stack_data["Status"] = elk_data["StackCreationStatus"]
    else:
        if "EndpointTestingStartTime" in elk_data:
            elk_data["StackCreationStatus"] = "Success"
            stack_data["Status"] = "Success"
        else:
            elk_data["StackCreationStatus"] = "Failure"
            stack_data["Status"] = "Failure"

    if "EndTime" in stack_data:
        dt = stack_data["EndTime"]
    else:
        dt = stack_data["StartTime"]

    # Calculate Time between failures & Time to recover
    if elk_data["StackCreationStatus"] == "Success":
        # TBF = Time Between Failures
        # Time interval between failure to failure between jobs
        stack_data["TBF"] = 0
        # TRR = Time To Recover. Check the previous job failed. And if
        # how long it took to recover
        stack_data["TTR"] = s_ttr("StackCreation", s3, bucket, project_name, build_number, subdirs, dt)
        #
        # Stack output
        #
        if "StackOutputs" in elk_data:
            output_data["StackOutput"] = elk_data["StackOutputs"]

        if "StackId" in elk_data:
            output_data["StackOutput"]["Id"] = elk_data["StackId"]
            output_data["StackOutput"]["Name"] = elk_data["StackId"].split('/')[-2]

        output_data["Type"] = "StackOutput"
        output_data["PipelineId"] = project_name + "-" + build_number

        #
        # Endpoint testing
        #
        if "EndpointTestingStartTime" in elk_data:
            test_data["ProjectName"] = args.project_name
            test_data["Type"] = "EndpointTesting"
            test_data["CustomerName"] = "REAN"
            test_data["PipelineName"] = "Daily Auto Testing"
            test_data["JobName"] = build_number
            test_data["PipelineId"] = project_name + "-" + build_number
            test_data["StartTime"] = iso_dt(elk_data["EndpointTestingStartTime"])
            test_data["EndTime"] = iso_dt(elk_data["EndpointTestingEndTime"])
            test_data["Duration"] = to_mins(elk_data["EndpointTestingDuration"])
            test_data["Status"] = elk_data["EndpointTestingStatus"]
            dt = test_data["EndTime"]

            if elk_data["EndpointTestingStatus"] != "Success":
                test_data["TTR"] = 0
                test_data["TBF"] = s_tbf("EndpointTesting", s3, bucket, project_name, build_number, subdirs, dt)
            else:
                test_data["TBF"] = 0
                test_data["TTR"] = s_ttr("EndpointTesting", s3, bucket, project_name, build_number, subdirs, dt)
    # in case the elk_data["StackCreationStatus"] != "Success":
    else:
        stack_data["TTR"] = 0
        stack_data["TBF"] = s_tbf("StackCreation", s3, bucket, project_name, build_number, subdirs, dt)

    job_data["State"] = stack_data["Status"]
    # in case
    if "Status" in test_data and test_data["Status"] != "Success":
        job_data["State"] = "Failure"

    with open('stack_creation.json', 'w') as f:
        f.write(json.dumps(stack_data))

    if (bool(test_data)):
        with open('endpoint_testing.json', "w") as f:
            f.write(json.dumps(test_data))

    if (bool(output_data)):
        with open('stack_output.json', "w") as f:
            f.write(json.dumps(output_data))

    if (bool(job_data)):
        with open('job_status.json', "w") as f:
            f.write(json.dumps(job_data))


# From reformat_json.py
def file_exists_in_s3(s3, bucket, project_name, _subdir, _file):
    exists = False
    try:
        s3.Object(bucket, project_name + '/' + _subdir + '/' + _file).load()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            exists = False
        else:
            raise
    else:
        exists = True
    return exists


# From reformat_json.py
def get_file_from_s3(s3, bucket, project_name, _subdir, _file):
    return s3.Object(bucket, project_name + '/' + _subdir + '/' + _file).get()['Body']


# From reformat_json.py
def iso_dt(dt_str):
    dt_tmp = dt_str.replace("+00:00", "")
    iso_dt_str = datetime.datetime.strptime(dt_tmp, "%Y-%m-%d %H:%M:%S.%f").isoformat() + "+00:00"
    return iso_dt_str


# From reformat_json.py
def to_mins(tm_str):
    tmp_tm = datetime.datetime.strptime(tm_str, "%H:%M:%S.%f").time()
    min_str = float("{0:.4f}".format(((tmp_tm.hour * 60 * 60) + (tmp_tm.minute * 60) + tmp_tm.second + (tmp_tm.microsecond / float(1000000))) / float(60)))
    return min_str


# From reformat_json.py
def above_file(key, s3, bucket, project_name, build_number, subdirs, idx):
    idx1 = idx + 1
    if idx1 < len(subdirs):
        _subdir = subdirs[idx1]
    else:
        return (False, 0)

    if key == "StackCreation":
        if file_exists_in_s3(s3, bucket, project_name, _subdir, 'stack_creation.json'):
            f = get_file_from_s3(s3, bucket, project_name, _subdir, 'stack_creation.json')
            data = json.loads(f.read())
            if "EndTime" in data:
                return (True, data["EndTime"])
            else:
                return (True, data["StartTime"])
        else:
            return (False, 0)
    elif key == "EndpointTesting":
        if file_exists_in_s3(s3, bucket, project_name, _subdir, 'endpoint_testing.json'):
            f = get_file_from_s3(s3, bucket, project_name, _subdir, 'endpoint_testing.json')
            data = json.loads(f.read())
            if "EndTime" in data:
                return (True, data["EndTime"])
            else:
                return (True, data["StartTime"])
        else:
            return (False, 0)


# From reformat_json.py
def s_ttr(key, s3, bucket, project_name, build_number, subdirs, endtime, rec=False):
    '''
    Function goes recursly through all previous existing job metrics folders in
    S3 to find the newest build that was successfull. This way the
    time-to-recover metrics can be calculated
    TTR = Time To Recover
    subdirs = all existing build numbers in this s3 folder
    '''
    idx = subdirs.index(build_number)
    if idx == 0:
        return 0
    _build_number = subdirs[idx - 1]

    if key == "StackCreation":
        if file_exists_in_s3(s3, bucket, project_name, _build_number, 'stack_creation.json'):
            f = get_file_from_s3(s3, bucket, project_name, _build_number, 'stack_creation.json')
            data = json.loads(f.read())
        else:
            return s_ttr(key, s3, bucket, project_name, _build_number, subdirs, endtime, rec=True)
    elif key == "EndpointTesting":
        if file_exists_in_s3(s3, bucket, project_name, _build_number, 'endpoint_testing.json'):
            f = get_file_from_s3(s3, bucket, project_name, _build_number, 'endpoint_testing.json')
            data = json.loads(f.read())
        else:
            return s_ttr(key, s3, bucket, project_name, _build_number, subdirs, endtime, rec=True)

    # The only case when rec=False is on the first execution. Returns 0
    # in case the previous job was also successful
    if not rec and data["Status"] == "Success":
        return 0
    elif rec and data["Status"] == "Success":
        end1 = datetime.datetime.strptime(endtime.replace("+00:00", ""), "%Y-%m-%dT%H:%M:%S.%f")
        if_above, dtime = above_file(key, s3, bucket, project_name, build_number, subdirs, idx - 1)
        if if_above:
            end2 = datetime.datetime.strptime(dtime.replace("+00:00", ""), "%Y-%m-%dT%H:%M:%S.%f")
            hrs = ((end1 - end2).total_seconds()) / float(60 * 60)
            return float("{0:.2f}".format(hrs))
        else:
            return 0
    else:
        return s_ttr(key, s3, bucket, project_name, _build_number, subdirs, endtime, rec=True)


# From reformat_json.py
def s_tbf(key, s3, bucket, project_name, build_number, subdirs, endtime, rec=False):
    '''
    Calculates the time between failures of jobs
    '''
    idx = subdirs.index(build_number)
    if idx == 0:
        return 0
    _build_number = subdirs[idx - 1]

    if key == "StackCreation":
        if file_exists_in_s3(s3, bucket, project_name, _build_number, 'stack_creation.json'):
            f = get_file_from_s3(s3, bucket, project_name, _build_number, 'stack_creation.json')
            data = json.loads(f.read())
        else:
            return s_tbf(key, s3, bucket, project_name, _build_number, subdirs, endtime, rec=True)
    elif key == "EndpointTesting":
        if file_exists_in_s3(s3, bucket, project_name, _build_number, 'endpoint_testing.json'):
            f = get_file_from_s3(s3, bucket, project_name, _build_number, 'endpoint_testing.json')
            data = json.loads(f.read())
        else:
            return s_tbf(key, s3, bucket, project_name, _build_number, subdirs, endtime, rec=True)

    # The only case when rec=False is on the first execution
    if not rec and data["Status"] == "Failure":
        if "EndTime" in data:
            dt = data["EndTime"]
        else:
            dt = data["StartTime"]
        end1 = datetime.datetime.strptime(endtime.replace("+00:00", ""), "%Y-%m-%dT%H:%M:%S.%f")
        end2 = datetime.datetime.strptime(dt.replace("+00:00", ""), "%Y-%m-%dT%H:%M:%S.%f")
        hrs = ((end1 - end2).total_seconds()) / float(60 * 60)
        return float("{0:.2f}".format(hrs))
    elif not rec and data["Status"] == "Success":
        return s_tbf(key, s3, bucket, project_name, _build_number, subdirs, endtime, rec=True)
    elif rec and data["Status"] == "Failure":
        if "EndTime" in data:
            dt = data["EndTime"]
        else:
            dt = data["StartTime"]
        end1 = datetime.datetime.strptime(endtime.replace("+00:00", ""), "%Y-%m-%dT%H:%M:%S.%f")
        end2 = datetime.datetime.strptime(dt.replace("+00:00", ""), "%Y-%m-%dT%H:%M:%S.%f")
        hrs = ((end1 - end2).total_seconds()) / float(60 * 60)
        return float("{0:.2f}".format(hrs))
    else:
        return s_tbf(key, s3, bucket, project_name, _build_number, subdirs, endtime, rec=True)


def uploadMetrics(args):
    files = {'stack_creation.json',
             'stack_output.json',
             'endpoint_testing.json',
             'job_status.json'}
    bucket = args.bucket
    project_name = args.project_name
    build_number = args.build_number
    client = boto3.client('s3')
    upload_failed = False

    for file in files:
        if os.path.isfile(file):
            try:
                client.upload_file(file, bucket, project_name + '/' + build_number + '/' + file)
            except boto3.exceptions.S3UploadFailedError as e:
                logging.fatal('Failed to upload file to S3: %s', e)
                upload_failed = True
        else:
            logging.info("File %s does not exists. Should be fine with stack_output.json + endpoint_testing.json", file)

    if upload_failed:
        exit(1)


if __name__ == "__main__":
    args = get_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)

    # get sts credentials in case we need them
    if args.assume_role:
        stsCred = assumeRole(args.assume_role)
        cf_client = boto3.client('cloudformation',
                                 aws_access_key_id=stsCred['AccessKeyId'],
                                 aws_secret_access_key=stsCred['SecretAccessKey'],
                                 aws_session_token=stsCred['SessionToken'])
    else:
        cf_client = boto3.client('cloudformation')

    #
    # Steps based on original documentation from 2017-01-25
    #   https://reancloud.atlassian.net/wiki/display/CUS/How+the+Rean+Test+Drives+Automated+Testing+Pipeline+Data+is+Ingested+by+RADAR
    #

    # shell-1: start stack. not needed here
    # shell-2: get stack output & create properties file from it
    stackMetricsJson = stackoutputs(args, cf_client)
    # shell-3: inject environment variables. not needed here
    # shell-4: endpoint testing
    endPointTestingData = endPointTesting(args, stackMetricsJson)

    # shell-5: executing 3 scripts
    #       outputs.py = stackOutputs()
    #       merge_json = combineMetrics()
    #       reformat_json.py = reformat_json()
    stackData = stackData(args, endPointTestingData, cf_client)
    elk_outputs = combineMetrics(stackData, stackMetricsJson)
    # since we upload to a bucket in the aha-control account remove aha-credentials
    # TODO: unset AWS_SECRET_ACCESS_KEY AWS_ACCESS_KEY_ID AWS_SESSION_TOKEN
    # reformat calculates TTR & TBF & creates files to be ingested by RADAR
    reformat_json(args, elk_outputs)
    # shell-5 finished here

    # TODO: shell-6: upload files to s3
    uploadMetrics(args)

    # shell-7: delete stack
    # in case of a failure: got integrated into stackData()
