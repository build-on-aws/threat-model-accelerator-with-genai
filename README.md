## Threat Model Accelerator with GenAI

### Highlights

* You may follow instructions below to quickly launch a web app for threat modeling accelerator
* What it does is to allow you input application template files to automatically generate a threat model baseline for your app
* Behind the scenes the web app interact with LLM powered by [Amazon Bedrock](https://aws.amazon.com/bedrock/)

### Note

If you want to access full version of the solution guidance, please view the following AWS Community blog post:
[XXXXXX]

### Prepare the environment on your local laptop 

Following commands assume you use MAC OS, with Python3 and pip3 installed.

* Step 1: Install Streamlit
`pip3 install -r requirements.txt`

* Step 2: Test streamlit:
`streamlit hello`

* Step 3: Run the Steamlit web app
`streamlit run app-tm.py`

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

