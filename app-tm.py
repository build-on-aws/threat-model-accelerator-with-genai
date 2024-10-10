import streamlit as st
import boto3
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from botocore.exceptions import ClientError
from botocore.credentials import Credentials
import os

# Retrieve credentials from environment variables
aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
aws_session_token = os.environ.get('AWS_SESSION_TOKEN')  # Include this if using temporary credentials, e.g. IAM Role
region_name = os.environ.get('AWS_REGION', 'us-east-1')

bedrock_client = boto3.client(
    'bedrock-runtime',
    region_name=region_name,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    aws_session_token=aws_session_token
)

# Allow user to upload CFN template file to describe the application
def file_uploader():
    st.subheader("Please upload the IaC file for your application (e.g. [CloudFormation](https://aws.amazon.com/cloudformation/), [Terraform](https://www.terraform.io/), or [OpenAPI](https://swagger.io/specification/) template file)")
    
    uploaded_file = st.file_uploader("Choose a IaC template file (.yaml or .json)")
    if uploaded_file is not None:
        # To read file as bytes:
        bytes_data = uploaded_file.getvalue()
        return bytes_data
    else:
        return None

# Allow user to download the threat model evaluation results into a json file
def download_json(dict_data):
    # Convert dict to JSON string
    json_str = json.dumps(dict_data, indent=4)
    
    # Create a download button
    st.download_button(
        label="Download Results into JSON file",
        file_name="threat_analysis_results.json",
        mime="application/json",
        data=json_str,
    )

# Extract threat model analysis data from the LLM response, while returning it as a 'Dict' viariable
def llm_response_parser(llm_response):
    #Find the start and end of the JSON content
    start_index = llm_response.find('{')
    end_index = llm_response.rfind('}') + 1

    #Extract the LLM response string
    llm_response_string = llm_response[start_index:end_index]

    #Parse the JSON string into a Python dictionary
    json_data = json.loads(llm_response_string)

    return(json_data)

# Transform the JSON data into a pandas dataframe for easier data manipulation and analysis
# And print it in the Streamlit GUI
def extract_stride_dataframe(json_data):

    # Initialize lists to store the extracted data
    categories = []
    total_threats = []
    high_risks = []
    medium_risks = []
    low_risks = []

    # Extract the required information
    for category, threats in json_data.items():
        categories.append(category)
        total_threats.append(len(threats))
        
        high_count = sum(1 for threat in threats.values() if threat['priority'] == 'High')
        medium_count = sum(1 for threat in threats.values() if threat['priority'] == 'Medium')
        low_count = sum(1 for threat in threats.values() if threat['priority'] == 'Low')
        
        high_risks.append(high_count)
        medium_risks.append(medium_count)
        low_risks.append(low_count)

    # Create a DataFrame
    df = pd.DataFrame({
        'Threat Category': categories,
        'Total Threats': total_threats,
        'High Risk Threats': high_risks,
        'Medium Risk Threats': medium_risks,
        'Low Risk Threats': low_risks
    })

    return(df)

# Present a histogram view to demonstrate threat data
def present_histogram_threats(df):
    # Streamlit UI
    st.subheader("Summary - STRIDE Threats Discovered")

    # Create a bar chart
    fig, ax = plt.subplots(figsize=(10, 6))
    threat_categories = df["Threat Category"]
    high_risk_threats = df["High Risk Threats"]
    medium_risk_threats = df["Medium Risk Threats"]
    low_risk_threats = df["Low Risk Threats"]

    bar_width = 0.2
    index = np.arange(len(threat_categories))

    # Plot the low-risk threats
    low_risk_bars = ax.bar(index - bar_width, low_risk_threats, bar_width, label="Low Risk Threats", color="g")

    # Plot the medium-risk threats
    medium_risk_bars = ax.bar(index, medium_risk_threats, bar_width, label="Medium Risk Threats", color="y")

    # Plot the high-risk threats
    high_risk_bars = ax.bar(index + bar_width, high_risk_threats, bar_width, label="High Risk Threats", color="r")

    ax.set_xlabel("Threat Category")
    ax.set_ylabel("Number of Threats")
    ax.set_title("STRIDE Threats Breakdown by Priority")
    ax.set_xticks(index)
    ax.set_xticklabels(threat_categories)
    ax.legend()

    # Set y-axis tick labels to integers
    max_threat_severity_count = max(max(high_risk_threats), max(medium_risk_threats), max(low_risk_threats))
    ax.set_yticks(range(max_threat_severity_count + 2))

    # Adjust the spacing between bars
    fig.tight_layout()

    # Display the plot in Streamlit
    st.pyplot(fig)

# Use LLM to evaluate application's threat model
def threat_model_evaluation(prompt):
    # Set the model ID for Claude 3 Sonnet
    model_id = "anthropic.claude-3-sonnet-20240229-v1:0"

    # Prepare the request payload
    request_body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.3,
    })

    # Invoke the model
    try:
        # Invoke the model with the request.
        response = bedrock_client.invoke_model(modelId=model_id, body=request_body)
    except (ClientError, Exception) as e:
        print(f"ERROR: Can't invoke '{model_id}'. Reason: {e}")
        exit(1)

    # Parse and return the response
    response_body = json.loads(response['body'].read())
    return response_body['content'][0]['text']

# Analyse the STRIDE model based on CFN template input, and render findings in the page
def threat_model_rendering(category, details):
    """
    Enlarges the content when the cursor hovers over it and adds an expander for more information.
    """
    style = """
    <style>
    .item {
        border: 1px solid #ccc;
        padding: 10px;
        transition: transform 0.2s ease;
        margin-bottom: 10px;
    }
    .item:hover {
        transform: scale(1.02);
    }
    .priority-high {
        color: red;
        font-weight: bold;
    }
    .priority-medium {
        color: orange;
        font-weight: bold;
    }
    .priority-low {
        color: green;
        font-weight: bold;
    }
    .threat-header {
        font-size: 1.3em;
        font-weight: bold;
        margin-bottom: 10px;
    }
    </style>
    """
    st.markdown(style, unsafe_allow_html=True)
    
    descriptions = {
        "Spoofing": "Impersonation of something or someone else.",
        "Tampering": "Modifying data or code without authorization.",
        "Repudiation": "Denying having performed an action.",
        "Information Disclosure": "Exposing information to unauthorized individuals.",
        "Denial of Service": "Denying or degrading service to users.",
        "Elevation of Privilege": "Gaining capabilities without proper authorization."
    }
    
    description = descriptions.get(category, "No description available.")
    
    content = f"""
    <h3>{category}</h3>
    <p><em>{description}</em></p>
    """
    st.markdown(f'<div class="item">{content}</div>', unsafe_allow_html=True)
    
    for threat_id, threat_details in details.items():
        with st.expander(f"Threat: {threat_id}"):
            st.markdown(f'<div class="threat-header">Threat: {threat_id}</div>', unsafe_allow_html=True)
            
            st.markdown(f"**Description:** {threat_details['description']}")
            
            priority = threat_details['priority']
            priority_class = f"priority-{priority.lower()}"
            st.markdown(f"**Priority:** <span class='{priority_class}'>{priority}", unsafe_allow_html=True)
            
            st.markdown("**Remediations:**")
            for remediation in threat_details['remediations']:
                st.markdown(f"- {remediation}")


# Threat Model Mate App
def main():
    st.title("Threat Modeling Mate (TMM)")

    # Request user to upload the CloudFormation template file for application threat model evaluation
    input_file = file_uploader()

    prompt_msg = f"""You are a trusted AWS security expert specialised in threat modeling.
    Now you need to evaluate the threat model of the application defined by the following CloudFormation template:
    {input_file.decode('utf-8') if input_file else None}
    
    Please provide a comprehensive threat modeling report that includes:
    1. [Threats] identified based on the STRIDE categories, including "Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege";
    2. [Priority] of each threat discovered, ranging from "High", "Medium", "Low";
    3. Relevant [mitigation] strategies for each identified threat; 
    
    IMPORTANT: Organize the output strictly in json format. The following is an example:
    
    "Spoofing": 
      "threat 1": 
        "description": "threat 1 description",
        "priority": "priority value",
        "remediations": ["remediation 1", "remediation 2", ..., "remediation n"]
      ,
      "threat 2": 
        "description": "threat 2 description",
        "priority": "priority value",
        "remediations": ["remediation 1", "remediation 2", ..., "remediation n"]
      ,
      ...,
      "threat n": 
        "description": "threat n description",
        "priority": "priority value",
        "remediations": ["remediation 1", "remediation 2", ..., "remediation n"]
    """

    # Only execute the following part when user input a template file.
    if(input_file):
        # LLM analyse on the application threat model and respond in Dictionary format
        response_msg = llm_response_parser(threat_model_evaluation(prompt_msg))

        # Download the response as JSON file
        download_json(response_msg)
        st.divider()

        # Get the summary of analysis result in dataframe format
        threat_df = extract_stride_dataframe(response_msg)

        # Print the histogram view of threats
        present_histogram_threats(threat_df)

        # Print the summary table for threats discoverd
        st.write(threat_df)
        st.divider()

        # Set a subheader for the section
        st.subheader("Threats and remediations details based on [Stride Model](https://en.wikipedia.org/wiki/STRIDE_model)")

        # Parse the response and render in the page
        for category, details in response_msg.items():
            threat_model_rendering(category, details)
      
# Application running
if __name__ == "__main__":
    main()