## Threat Model Accelerator with GenAI

### Highlights

* You may follow instructions below to quickly launch a web app for threat modeling accelerator
* What it does is to allow you input application template files to automatically generate a threat model baseline for your app
* Behind the scenes the web app interact with LLM powered by [Amazon Bedrock](https://aws.amazon.com/bedrock/)

### Note

* If you want to access full version of the solution guidance, please view the following AWS Community blog post:
[XXXXXXXXXXXXXXXXXXXXXX]

* Watch this video to help you install the Threat Model Mate web app:
https://youtu.be/drSHpXuSkOc

### Prepare the environment on your local laptop 

Following commands assume you use MAC OS, with Python3 and pip3 installed.

* Step 1: Install Streamlit
`pip3 install -r requirements.txt`

* Step 2: Test streamlit:
`streamlit hello`

* Step 3: Run the Steamlit web app
`streamlit run app-tm.py`

## Solution architect view
![Solution architect view](/images/solution_topology.png "Solution architect view.")

## Web app GUI view
![Web app GUI view](/images/threat-modeling-mate-1.png "Web app GUI view.")

## Common issue

**Question** When I execute the web app, I've got following error. Why?
```ERROR: Can't invoke 'anthropic.claude-3-sonnet-20240229-v1:0'. Reason: An error occurred (AccessDeniedException) when calling the InvokeModel operation: You don't have access to the model with the specified model ID.```

**Answer** 
* This was caused by lacking temporary credentials in your command line tool when running `streamlit run app-tm.py`.
* Please refer to following docs to provide temporary credentials (e.g. )
    1. [Use temporary credentials with AWS resources](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html)
    2. [GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html)



## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

