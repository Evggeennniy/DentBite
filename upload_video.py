def upload_file(filename):
    import os
    import boto3
    from dotenv import load_dotenv

    load_dotenv()

    digital_ocean_secret_key = os.getenv('DIGITAL_OCEAN_SECRET_KEY')
    digital_ocean_access_key = os.getenv('DIGITAL_OCEAN_ACCESS_KEY')

    session = boto3.session.Session()
    client = session.client('s3',
                            region_name='nyc3',
                            endpoint_url='https://nyc3.digitaloceanspaces.com',
                            aws_access_key_id=digital_ocean_access_key,
                            aws_secret_access_key=digital_ocean_secret_key)

    filepath = './tmp/'
    full_path = filepath + filename

    try:
        client.upload_file(full_path, 'dentbitestaticfiles', f'static/videos/{filename}',
                           ExtraArgs={'ACL': 'public-read'})
        print("File uploaded successfully.")
        os.remove(full_path)
    except Exception as e:
        print(f"An error occurred: {e}")

