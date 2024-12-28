from flask import Blueprint, request, jsonify, flash, redirect, url_for, current_app, url_for, send_from_directory

from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, ApplyPatient, StaffApplication, PersonalInfo, Education, FormerEmployer, PersonalReference, ProfessionalKnowledge, CriminalBackground, StaffAuthorization, EmployeeData, HipaaData, Verification, JobAgreement, NurseAgreement, RegisteredNurseAgreement, HandBook

from sqlalchemy import text
from werkzeug.utils import secure_filename
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from functools import wraps
import jwt
import json
import os
from datetime import datetime, timedelta
from . import db

main = Blueprint("main", __name__)

@main.route("/", methods=["GET"])
def home():
    return "Hello from the Home Route", 200

    


@main.route("/registered", methods=["POST"])
def registered():
    print("ok")
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

  

    if not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    # Check if user already exists (email check only)
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 400


    # Create new user
    new_user = User(email=email, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201




# Utility function to verify the JWT token
def verify_token(token):
    try:
        # Decode the token using the secret key from Flask's app config
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Create the /validate-session API endpoint
@main.route('/validate-session', methods=['POST'])
def validate_session():
    # Get the token from the request headers or body
    token = request.headers.get('Authorization')  # or request.json.get('token') for body request

    if not token:
        return jsonify({"error": "Token is missing"}), 400

    # Validate the token
    payload = verify_token(token)

    if payload:
        # If the token is valid, return a success response with the role
        return jsonify({"valid": True, "role": payload.get("role")}), 200
    else:
        # If the token is invalid or expired, return an error response
        return jsonify({"valid": False, "message": "Invalid or expired token"}), 401

@main.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()
    identifier = data.get("username")  # This can be username or email
    print("identifier: ", identifier)

    password = data.get("password")
  
    if not identifier or not password:
        return jsonify({"error": "Missing identifier or password"}), 400

    # Check if identifier matches a username (for admin) or email (for user)
    user = User.query.filter(
        ((User.role == "admin") & (User.username == identifier)) | 
        ((User.role == "user") & (User.email == identifier))
    ).first()

    if not user:
        return jsonify({"error": "Invalid identifier or user not found"}), 404

    print("user.username: ", user.username)
    print("user.password :", user.password)
    print(user.role)

    # Verify password (hashing is recommended here)
    if user.password != password:
        return jsonify({"error": "Invalid password"}), 401

    # Generate access token
    token = create_access_token(identity={"id": user.id, "role": user.role})
    
    return jsonify({
        "message": "Login successful!",
        "token": token,
        "role": user.role  # Return role for frontend use
    }), 200


@main.route("/user-login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")  # Use email for login
    password = data.get("password")
  
    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400

    # Find the user by email
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "Invalid email or user not found"}), 404

    # Verify password (hashing should be used in production)
    if user.password != password:
        return jsonify({"error": "Invalid password"}), 401

    # Generate access token with expiration time
    expires = timedelta(hours=6)  # Set token to expire in 1 hour
    token = create_access_token(identity={"id": user.id, "category": user.category}, expires_delta=expires)

    
    return jsonify({
        "message": "Login successful!",
        "token_user": token,
        "category": user.category  # Return user's category
    }), 200



@main.route('/registered_users')
def registered_users():
    # Update query to exclude users with the 'admin' category
    query = text("SELECT email, password FROM user where role != 'admin'")
    result = db.session.execute(query).fetchall()
    
    users = []
    for row in result:
        users.append({
            'email': row[0],      # email is the first column (index 0)
            'password': row[1],   # password is the second column (index 1)
        })
    
    return jsonify(users)


@main.route('/apply_patients', methods=['POST'])
def apply_patients():
  
    data = request.get_json()
    try:
        new_patient = ApplyPatient(
            first_name=data['patientFirstName'],
            last_name=data['patientLastName'],
            email=data['patientEmail'],
            phone=data['patientPhone'],
            take_over=data['patientTakeOver'],
            gender=data['patientGender'],
            age=data['patientAge'],
            pdn=data.get('patientPDN', ''),
            pcs=data.get('patientPCS', ''),
            living_situation=data['patientLivingSituation'],
            care_plan=data['patientCarePlan'],
            experience=data['experience'],
            paid_status=data['patientPaidStatus'],
            availability=data['patientAvailability'],
        )
        db.session.add(new_patient)
        db.session.commit()
        return jsonify({'message': 'Patient application saved successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
@main.route('/get_patients_applications', methods=['GET'])
def get_patients_applications():
   
    patients = ApplyPatient.query.all()
    
    patients_data = []
    
    for patient in patients:
        patients_data.append({
            "id": patient.id,
            "first_name": patient.first_name,
            "last_name": patient.last_name,
            "email": patient.email,
            "phone": patient.phone,
            "take_over": patient.take_over,
            "gender": patient.gender,
            "age": patient.age,
            "pdn": patient.pdn,
            "pcs": patient.pcs,
            "living_situation": patient.living_situation,
            "care_plan": patient.care_plan,
            "experience": patient.experience,
            "paid_status": patient.paid_status,
            "availability": patient.availability,
            "created_at": patient.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify(patients_data)

@main.route('/staff_applications', methods=['POST'])
def staff_application():
    try:
        # Parse form data
        form_data = request.form.to_dict()
        resume_file = request.files.get('resume')


         # Convert start_date string to a Python date object
        start_date_str = form_data.get('startDate', None)
        start_date = None
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()  # Format 'YYYY-MM-DD'


        # Save the resume file
        resume_path = None
        if resume_file:
            filename = secure_filename(resume_file.filename)
            resume_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            resume_file.save(resume_path)

        # Create a new application record
        new_application = StaffApplication(
            first_name=form_data['firstName'],
            last_name=form_data['lastName'],
            email=form_data['email'],
            phone=form_data['phone'],
            address=form_data.get('address', ''),
            communication=form_data['communication'],
            experience=form_data.get('experience', ''),
            position=form_data['position'],
            start_date=start_date,
            additional_info=form_data.get('additionalInfo', ''),
            is_over_18=form_data['isOver18'] == 'true',
            is_eligible_to_work=form_data['isEligibleToWork'] == 'true',
            ref1_name=form_data.get('ref1Name', ''),
            ref1_phone_number=form_data.get('ref1PhoneNumber', ''),
            ref2_name=form_data.get('ref2Name', ''),
            ref2_phone_number=form_data.get('ref2PhoneNumber', ''),
            resume_path=resume_path
        )
        # print("haha")
        # for key, value in form_data.items():
        #     print(key, value)
       
        db.session.add(new_application)
        db.session.commit()

        return jsonify({'message': 'Application submitted successfully!'}), 201

    except Exception as e:
        print(f"Error: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@main.route('/static/uploads/resumes/<filename>')
def uploaded_file(filename):

    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename, as_attachment=False
                               )

# @main.route('/uploads/<filename>')
# def upload(filename):
#     return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

def serialize_staff_application(application):
    """
    Serialize a StaffApplication object into a dictionary with full resume_path URL.
    """
    return {
        'id': application.id,
        'first_name': application.first_name,
        'last_name': application.last_name,
        'email': application.email,
        'phone': application.phone,
        'address': application.address,
        'communication': application.communication,
        'experience': application.experience,
        'position': application.position,
        'start_date': application.start_date.strftime('%Y-%m-%d') if application.start_date else None,
        'additional_info': application.additional_info,
        'is_over_18': application.is_over_18,
        'is_eligible_to_work': application.is_eligible_to_work,
        'ref1_name': application.ref1_name,
        'ref1_phone_number': application.ref1_phone_number,
        'ref2_name': application.ref2_name,
        'ref2_phone_number': application.ref2_phone_number,
        'resume_path': url_for('main.uploaded_file', filename=application.resume_path.split(os.sep)[-1], _external=True),
        'created_at': application.created_at.strftime('%Y-%m-%d %H:%M:%S') if application.created_at else None
    }



@main.route('/staff_applications', methods=['GET'])
def get_all_staff_applications():
    """
    Retrieve all staff applications.
    """
    try:
        applications = StaffApplication.query.all()
        # Serialize applications using the helper function
        result = [serialize_staff_application(app) for app in applications]
        return jsonify(result), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500


@main.route('/staff_applications/<int:application_id>', methods=['GET'])
def get_staff_application(application_id):
    """
    Retrieve a specific staff application by ID.
    """
    try:
        application = StaffApplication.query.get(application_id)
        if not application:
            return jsonify({'error': 'Application not found'}), 404

        # Serialize application using the helper function
        result = serialize_staff_application(application)
        return jsonify(result), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500





# ----------------------------------------------------   Application Form    -------------------------------------------------------------

# Middleware to verify token
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        print("token: ", token)

        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, current_app.config['jude'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid'}), 403
        
        request.user_id = data['user_id']  # Add user_id to the request context
        return f(*args, **kwargs)
    
    return decorated_function

# @main.route('/application2', methods=['POST'])
# # @token_required
# def application2():
#     try:
#         # Get data from request
#         data = request.get_json()

#         token = request.headers.get('Authorization')
        

#         if not token:
#             return jsonify({'message': 'Token is missing'}), 403
        
#         try:
#             token = token.split(" ")[1]
#             decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
           
#         except jwt.ExpiredSignatureError:
#             print("Token has expired")
#             return jsonify({'message': 'You need to relog, go to home page, and come back here'}), 403
#         except jwt.InvalidTokenError as e:
#             print(f"Invalid token error: {e}")
#             return jsonify({'message': 'Token is invalid'}), 403
#         except Exception as e:
#             print(f"Error during token decoding: {e}")
#             return jsonify({'message': 'Token is invalid'}), 403

#         request.user_id = decoded_data['sub']['id']  # Add user_id to the request context

#         # Get logged-in user's ID
#         user_id = request.user_id
#         print("userid: ", user_id)

#         # print("User ID:", request.user_id)
#         # print("Full Name:", data['formData'].get('fullName'))
#         # print("SSN:", data['formData'].get('ssn'))
#         # print("Address:", data['formData'].get('address'))
#         # print("Number Street:", data['formData'].get('numberStreet'))
#         # print("City:", data['formData'].get('city'))
#         # print("State:", data['formData'].get('state'))
#         # print("Zip Code:", data['formData'].get('zipCode'))
#         # print("Referred By:", data['formData'].get('referredBy'))
#         # print("Salary Desired:", data['formData'].get('salaryDesired'))
#         # print("Position Category:", data['formData'].get('positionCategory'))
#         # print("Shift Desired:", data['formData'].get('shiftDesired'))
#         # print("Employed:", data['formData'].get('employed'))
#         # print("Contact Employer:", data['formData'].get('contactEmployer'))

#         try:
#             # Check if the user exists
#             # user = User.query.get(data['userId'])
#             # if not user:
#             #     return jsonify({'error': 'User not found'}), 400
#             print("above")
#             # Save personal info
#             personal_info = PersonalInfo(
#                 user_id=request.user_id,
#                 full_name=data['formData']['fullName'],
#                 ssn=data['formData']['ssn'],
#                 address=data['formData']['address'],
#                 number_street=data['formData']['numberStreet'],
#                 city=data['formData']['city'],
#                 state=data['formData']['state'],
#                 zip_code=data['formData']['zipCode'],
#                 referred_by=data['formData']['referredBy'],
#                 salary_desired=data['formData']['salaryDesired'],
#                 position_category=data['formData']['positionCategory'],
#                 shift_desired=data['formData']['shiftDesired'],
#                 employed=data['formData']['employed'],
#                 contact_employer=data['formData']['contactEmployer']
#             )

#             db.session.add(personal_info)

#             print("below")

#             # Save education data
#             for edu in data['educationData']:
#                 education = Education(
#                     user_id=request.user_id,
#                     level=edu['level'],
#                     school=edu['school'],
#                     year=edu['year'],
#                     degree=edu['degree']
#                 )
#                 db.session.add(education)

#             # Save former employers
#             for emp in data['formerEmployers']:
#                 former_employer = FormerEmployer(
#                     user_id=request.user_id,
#                     from_date=emp['from'],
#                     to_date=emp['to'],
#                     employer=emp['employer'],
#                     phone=emp['phone'],
#                     position=emp['position'],
#                     salary=emp['salary'],
#                     reason=emp['reason']
#                 )
#                 db.session.add(former_employer)

#             # Save personal references
#             for ref in data['personalReferences']:
#                 personal_ref = PersonalReference(
#                     user_id=request.user_id,
#                     name=ref['name'],
#                     address=ref['address'],
#                     phone=ref['phone'],
#                     business=ref['business'],
#                     years_known=ref['yearsKnown']
#                 )
#                 db.session.add(personal_ref)

#             # Save professional knowledge
#             for prof in data['professionalKnowledge']:
#                 professional_knowledge = ProfessionalKnowledge(
#                     user_id=request.user_id,
#                     category=prof['category'],
#                     years_of_experience=prof['yearsOfExperience'],
#                     specifics=prof['specifics']
#                 )
#                 db.session.add(professional_knowledge)

#             # Commit all data to the database
#             db.session.commit()

#             return jsonify({'message': 'Data saved successfully'}), 200

#         except Exception as e:
#             db.session.rollback()  # Rollback the transaction on error
#             print(f"Error during commit: {e}")
#             return jsonify({'error': 'Something went wrong'}), 500

        
#     except Exception as e:
#         db.session.rollback()  # Rollback in case of error
#         return jsonify({'message': f'An error occurred: {str(e)}'}), 500
    
@main.route('/application2', methods=['POST'])
def application2():
    try:
        # Get data from request
        data = request.get_json()

        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        
        try:
            token = token.split(" ")[1]
            decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired. Please log in again.'}), 403
        except jwt.InvalidTokenError as e:
            return jsonify({'message': 'Invalid token.'}), 403

        user_id = decoded_data['sub']['id']  # Decoded user ID from token

        try:
            # Personal Info
            personal_info = PersonalInfo.query.filter_by(user_id=user_id).first()
            if personal_info:
                # Update existing record
                personal_info.full_name = data['formData']['fullName']
                personal_info.ssn = data['formData']['ssn']
                personal_info.address = data['formData']['address']
                personal_info.number_street = data['formData']['numberStreet']
                personal_info.city = data['formData']['city']
                personal_info.state = data['formData']['state']
                personal_info.zip_code = data['formData']['zipCode']
                personal_info.referred_by = data['formData']['referredBy']
                personal_info.salary_desired = data['formData']['salaryDesired']
                personal_info.position_category = data['formData']['positionCategory']
                personal_info.shift_desired = data['formData']['shiftDesired']
                personal_info.employed = data['formData']['employed']
                personal_info.contact_employer = data['formData']['contactEmployer']
            else:
                # Add new record
                personal_info = PersonalInfo(
                    user_id=user_id,
                    full_name=data['formData']['fullName'],
                    ssn=data['formData']['ssn'],
                    address=data['formData']['address'],
                    number_street=data['formData']['numberStreet'],
                    city=data['formData']['city'],
                    state=data['formData']['state'],
                    zip_code=data['formData']['zipCode'],
                    referred_by=data['formData']['referredBy'],
                    salary_desired=data['formData']['salaryDesired'],
                    position_category=data['formData']['positionCategory'],
                    shift_desired=data['formData']['shiftDesired'],
                    employed=data['formData']['employed'],
                    contact_employer=data['formData']['contactEmployer']
                )
                db.session.add(personal_info)

            # Education
            Education.query.filter_by(user_id=user_id).delete()
            for edu in data['educationData']:
                education = Education(
                    user_id=user_id,
                    level=edu['level'],
                    school=edu['school'],
                    year=edu['year'],
                    degree=edu['degree']
                )
                db.session.add(education)

            # Former Employers
            FormerEmployer.query.filter_by(user_id=user_id).delete()
            for emp in data['formerEmployers']:
                former_employer = FormerEmployer(
                    user_id=user_id,
                    from_date=emp['from'],
                    to_date=emp['to'],
                    employer=emp['employer'],
                    phone=emp['phone'],
                    position=emp['position'],
                    salary=emp['salary'],
                    reason=emp['reason']
                )
                db.session.add(former_employer)

            # Personal References
            PersonalReference.query.filter_by(user_id=user_id).delete()
            for ref in data['personalReferences']:
                personal_ref = PersonalReference(
                    user_id=user_id,
                    name=ref['name'],
                    address=ref['address'],
                    phone=ref['phone'],
                    business=ref['business'],
                    years_known=ref['yearsKnown']
                )
                db.session.add(personal_ref)

            # Professional Knowledge
            ProfessionalKnowledge.query.filter_by(user_id=user_id).delete()
            for prof in data['professionalKnowledge']:
                professional_knowledge = ProfessionalKnowledge(
                    user_id=user_id,
                    category=prof['category'],
                    years_of_experience=prof['yearsOfExperience'],
                    specifics=prof['specifics']
                )
                db.session.add(professional_knowledge)

            db.session.commit()
            return jsonify({'message': 'Data saved successfully'}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Something went wrong: {str(e)}'}), 500

    except Exception as e:
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500


@main.route('/get_personal_info', methods=['GET'])
def get_personal_info():
    try:
        # Query all personal info entries
        personal_infos = PersonalInfo.query.all()

        # Serialize data into JSON format
        data = [
            {
                "id": info.id,
                "full_name": info.full_name,
                "ssn": info.ssn,
                "address": info.address,
                "number_street": info.number_street,
                "city": info.city,
                "state": info.state,
                "zip_code": info.zip_code,
                "referred_by": info.referred_by,
                "salary_desired": info.salary_desired,
                "position_category": info.position_category,
                "shift_desired": info.shift_desired,
                "employed": info.employed,
                "contact_employer": info.contact_employer,
                "user_id": info.user_id,
            }
            for info in personal_infos
        ]

        return jsonify(data), 200
    except Exception as e:
        print(f"Error fetching personal info: {e}")
        return jsonify({"error": "Failed to fetch data"}), 500
    

@main.route('/get_education_info', methods=['GET'])
def get_education_info():
    try:
        # Query all education records from the database
        education_records = Education.query.all()
        
        # Serialize the education records into a list of dictionaries
        
        education_data = [
            {
                "id": edu.id,
                "level": edu.level,
                "school": edu.school,
                "year": edu.year,
                "degree": edu.degree,
                "user_id": edu.user_id,
            }
            for edu in education_records
        ]
     
        # Return the data as JSON
        return jsonify({"education": education_data}), 200
    except Exception as e:
        # Handle exceptions and return an error response
        return jsonify({"error": str(e)}), 500
    

@main.route('/get_former_employers', methods=['GET'])
def get_former_employers():
    try:
        # Query all former employer records from the database
        employer_records = FormerEmployer.query.all()

        # Serialize the records into a list of dictionaries
        employers_data = [
            {
                "id": employer.id,
                "from_date": employer.from_date,
                "to_date": employer.to_date,
                "employer": employer.employer,
                "phone": employer.phone,
                "position": employer.position,
                "salary": employer.salary,
                "reason": employer.reason,
                "user_id": employer.user_id
            }
            for employer in employer_records
        ]

        # Return the serialized data as JSON
        return jsonify({"former_employers": employers_data}), 200
    except Exception as e:
        # Handle any exceptions and return an error response
        return jsonify({"error": str(e)}), 500


@main.route('/get_professional_knowledge', methods=['GET'])
def get_professional_knowledge():
    try:
        # Query professional knowledge records for the current user
        knowledge_records = ProfessionalKnowledge.query.all()

        # Serialize the records into a list of dictionaries
        knowledge_data = [
            {
                "id": record.id,
                "category": record.category,
                "years_of_experience": record.years_of_experience,
                "specifics": record.specifics,
                "user_id": record.user_id
            }
            for record in knowledge_records
        ]
     

        # Return the serialized data as JSON
        return jsonify({"professional_knowledge": knowledge_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main.route('/get_personal_references', methods=['GET'])
def get_personal_references():
    try:
        personal_references = PersonalReference.query.all()

        # Serialize the results
        references = [
            {
                'id': ref.id,
                'name': ref.name,
                'address': ref.address,
                'phone': ref.phone,
                'business': ref.business,
                'years_known': ref.years_known,
                'user_id': ref.user_id
            }
            for ref in personal_references
        ]

        return jsonify({'personal_references': references})

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch personal references'}), 500
    


@main.route('/authorization', methods=['POST'])
def save_authorization_data():
    print()
    # Get data from request
    data = request.get_json()

    # Get the token from the Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    # Decode the token and extract the user_id
    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_data['sub']['id']  # Extract user ID from decoded data
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired. Please log in again.'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

    # Prepare the data for the staff authorization and criminal background
    authorization_data = data.get('authorizationData', {})
    criminal_background = data.get('criminalBackground', {})

    # Process StaffAuthorization
    staff_auth = StaffAuthorization.query.filter_by(user_id=user_id).first()
    if staff_auth:
        # Update the existing record
        staff_auth.first_name = authorization_data.get('firstName', staff_auth.first_name)
        staff_auth.middle_name = authorization_data.get('middleName', staff_auth.middle_name)
        staff_auth.last_name = authorization_data.get('lastName', staff_auth.last_name)
        staff_auth.date_of_birth = authorization_data.get('dateOfBirth', staff_auth.date_of_birth)
        staff_auth.ssn = authorization_data.get('ssn', staff_auth.ssn)
        staff_auth.drivers_license_number = authorization_data.get('driversLicenseNumber', staff_auth.drivers_license_number)
        staff_auth.state_issued = authorization_data.get('stateIssued', staff_auth.state_issued)
        staff_auth.former_names = authorization_data.get('formerNames', staff_auth.former_names)
        staff_auth.signature = authorization_data.get('signature', staff_auth.signature)
        staff_auth.signature_date = authorization_data.get('signatureDate', staff_auth.signature_date)
    else:
        # Create a new StaffAuthorization record
        staff_auth = StaffAuthorization(
            user_id=user_id,
            first_name=authorization_data.get('firstName'),
            middle_name=authorization_data.get('middleName'),
            last_name=authorization_data.get('lastName'),
            date_of_birth=authorization_data.get('dateOfBirth'),
            ssn=authorization_data.get('ssn'),
            drivers_license_number=authorization_data.get('driversLicenseNumber'),
            state_issued=authorization_data.get('stateIssued'),
            former_names=authorization_data.get('formerNames'),
            signature=authorization_data.get('signature'),
            signature_date=authorization_data.get('signatureDate'),
            created_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        )

    # Process CriminalBackground
    criminal_record = CriminalBackground.query.filter_by(user_id=user_id).first()
    if criminal_record:
        # Update the existing criminal record
        criminal_record.conviction = criminal_background.get('conviction', criminal_record.conviction)
        criminal_record.details = criminal_background.get('explanation', criminal_record.details)
        criminal_record.employee_signature = criminal_background.get('employeeSignature', criminal_record.employee_signature)
        criminal_record.signature_date = criminal_background.get('employeeSignatureDate', criminal_record.signature_date)
        criminal_record.representative_signature = criminal_background.get('representative', criminal_record.representative_signature)
        criminal_record.representative_date = criminal_background.get('representativeDate', criminal_record.representative_date)
    else:
        # Create a new CriminalBackground record
        criminal_record = CriminalBackground(
            user_id=user_id,
            conviction=criminal_background.get('conviction'),
            details=criminal_background.get('explanation'),
            employee_signature=criminal_background.get('employeeSignature'),
            signature_date=criminal_background.get('employeeSignatureDate'),
            representative_signature=criminal_background.get('representative'),
            representative_date=criminal_background.get('representativeDate'),
            created_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        )

    # Commit the changes to the database
    db.session.add(staff_auth)
    db.session.add(criminal_record)
    db.session.commit()

    return jsonify({"message": "Authorization and criminal background data saved successfully!"}), 200


@main.route('/get_authorization_and_criminal_data', methods=['GET'])
def get_authorization_and_criminal_data():
    try:
        # Fetch data from the staff_authorization table
        staff_authorization_data = StaffAuthorization.query.all()

        # Fetch data from the criminal_background table
        criminal_background_data = CriminalBackground.query.all()

        # Serialize the results from staff_authorization table
        staff_authorization = [
            {
                'id': auth.id,
                'user_id': auth.user_id,
                'first_name': auth.first_name,
                'middle_name': auth.middle_name,
                'last_name': auth.last_name,
                'date_of_birth': auth.date_of_birth,
                'ssn': auth.ssn,
                'drivers_license_number': auth.drivers_license_number,
                'state_issued': auth.state_issued,
                'former_names': auth.former_names,
                'signature': auth.signature,
                'signature_date': auth.signature_date,
                'created_at': auth.created_at
            }
            for auth in staff_authorization_data
        ]

        # Serialize the results from criminal_background table
        criminal_background = [
            {
                'id': cb.id,
                'user_id': cb.user_id,
                'conviction': cb.conviction,
                'details': cb.details,
                'employee_signature': cb.employee_signature,
                'signature_date': cb.signature_date,
                'representative_signature': cb.representative_signature,
                'representative_date': cb.representative_date,
                'created_at': cb.created_at
            }
            for cb in criminal_background_data
        ]

        # Return both datasets as a JSON response
        return jsonify({
            'staff_authorization': staff_authorization,
            'criminal_background': criminal_background
        })

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch data'}), 500
    

@main.route('/employee', methods=['POST'])
def save_employee_data():
    # Get data from request
    data = request.get_json()

    # Get the token from the Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    # Decode the token and extract the user_id
    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_data['sub']['id']  # Extract user ID from decoded data
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired. Please log in again.'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

    # Prepare data from the request body
    employee_data = data

    # Check if employee data exists for this user
    existing_data = EmployeeData.query.filter_by(user_id=user_id).first()
    if existing_data:
        # Update the existing record
        existing_data.insurance_company = employee_data.get('insuranceCompany', existing_data.insurance_company)
        existing_data.claims_representative_phone = employee_data.get('claimsRepresentativePhone', existing_data.claims_representative_phone)
        existing_data.policy_number = employee_data.get('policyNumber', existing_data.policy_number)
        existing_data.policy_expiration_date = employee_data.get('policyExpirationDate', existing_data.policy_expiration_date)
        existing_data.jd_representative = employee_data.get('jdRepresentative', existing_data.jd_representative)
        existing_data.coverage_verification_date = employee_data.get('coverageVerificationDate', existing_data.coverage_verification_date)
        existing_data.employee_name = employee_data.get('employeeName', existing_data.employee_name)
        existing_data.employee_signature = employee_data.get('employeeSignature', existing_data.employee_signature)
        existing_data.employee_signature_date = employee_data.get('employeeSignatureDate', existing_data.employee_signature_date)
        existing_data.jd_rep_name = employee_data.get('jdRepName', existing_data.jd_rep_name)
        existing_data.jd_rep_signature_date = employee_data.get('jdRepSignatureDate', existing_data.jd_rep_signature_date)
    else:
        # Create a new record
        new_employee_data = EmployeeData(
            user_id=user_id,
            insurance_company=employee_data.get('insuranceCompany'),
            claims_representative_phone=employee_data.get('claimsRepresentativePhone'),
            policy_number=employee_data.get('policyNumber'),
            policy_expiration_date=employee_data.get('policyExpirationDate'),
            jd_representative=employee_data.get('jdRepresentative'),
            coverage_verification_date=employee_data.get('coverageVerificationDate'),
            employee_name=employee_data.get('employeeName'),
            employee_signature=employee_data.get('employeeSignature'),
            employee_signature_date=employee_data.get('employeeSignatureDate'),
            jd_rep_name=employee_data.get('jdRepName'),
            jd_rep_signature_date=employee_data.get('jdRepSignatureDate'),
            created_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        )
        db.session.add(new_employee_data)

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": "Employee data saved successfully!"}), 200


@main.route('/get_employee_form_data', methods=['GET'])
def get_employee_data():
    try:
        # Fetch all employee data records
        employee_data = EmployeeData.query.all()

        # Check if data exists
        if employee_data:
            # Serialize all records into a list of dictionaries
            employee_records = [
                {
                    'id': auth.id,
                    'user_id': auth.user_id,
                    'insurance_company': auth.insurance_company,
                    'claims_representative_phone': auth.claims_representative_phone,
                    'policy_number': auth.policy_number,
                    'policy_expiration_date': auth.policy_expiration_date,
                    'jd_representative': auth.jd_representative,
                    'coverage_verification_date': auth.coverage_verification_date,
                    'employee_name': auth.employee_name,
                    'employee_signature': auth.employee_signature,
                    'employee_signature_date': auth.employee_signature_date,
                    'jd_rep_name': auth.jd_rep_name,
                    'jd_rep_signature_date': auth.jd_rep_signature_date,
                    'created_at': auth.created_at
                }
                for auth in employee_data
            ]

            # Return the list of serialized records
            return jsonify({'employee_data': employee_records }), 200
        else:
            return jsonify({'message': 'No employee data found'}), 404

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch data'}), 500
    

@main.route('/hipaa', methods=['POST'])
def save_hipaa_data():
    # Get data from request
    data = request.get_json()

    # Get the token from the Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    # Decode the token and extract the user_id
    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_data['sub']['id']  # Extract user ID from decoded data
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired. Please log in again.'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

    # Prepare data from the request body
    hipaa_data = data

    # Check if HIPAA data exists for this user
    existing_data = HipaaData.query.filter_by(user_id=user_id).first()
    if existing_data:
        # Update the existing record
        existing_data.decline_vaccination = hipaa_data.get('declineVaccination', existing_data.decline_vaccination)
        existing_data.employee_signature = hipaa_data.get('employeeSignature', existing_data.employee_signature)
        existing_data.date1 = hipaa_data.get('date1', existing_data.date1)
        existing_data.hipaa_acknowledgment = hipaa_data.get('hipaaAcknowledgment', existing_data.hipaa_acknowledgment)
        existing_data.hipaa_signature = hipaa_data.get('hipaaSignature', existing_data.hipaa_signature)
        existing_data.date2 = hipaa_data.get('date2', existing_data.date2)
    else:
        # Create a new record
        new_hipaa_data = HipaaData(
            user_id=user_id,
            decline_vaccination=hipaa_data.get('declineVaccination'),
            employee_signature=hipaa_data.get('employeeSignature'),
            date1=datetime.strptime(hipaa_data.get('date1'), '%Y-%m-%d') if hipaa_data.get('date1') else None,
            hipaa_acknowledgment=hipaa_data.get('hipaaAcknowledgment'),
            hipaa_signature=hipaa_data.get('hipaaSignature'),
            date2=datetime.strptime(hipaa_data.get('date2'), '%Y-%m-%d') if hipaa_data.get('date2') else None
        )
        db.session.add(new_hipaa_data)

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": "HIPAA data saved successfully!"}), 200


@main.route('/get_hipaa_data', methods=['GET'])
def get_hipaa_data():
    try:
        # Fetch all employee data records
        hipaa_data = HipaaData.query.all()

        # Check if data exists
        if hipaa_data:
            # Serialize all records into a list of dictionaries
            hipaa_records = [
                {
                    'id': auth.id,
                    'user_id': auth.user_id,
                    'decline_vaccination': auth.decline_vaccination,
                    'employee_signature': auth.employee_signature,
                    'date1': auth.date1,
                    'hipaa_acknowledgment': auth.hipaa_acknowledgment,
                    'hipaa_signature': auth.hipaa_signature,
                    'date2': auth.date2
                }
                for auth in hipaa_data
            ]

            # Return the list of serialized records
            return jsonify({'hipaa_data': hipaa_records }), 200
        else:
            return jsonify({'message': 'No employee data found'}), 404

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch data'}), 500
    



@main.route('/verification', methods=['POST'])
def save_verification_data():
    # Get data from request
    data = request.get_json()

    # Get the token from the Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    # Decode the token and extract the user_id
    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_data['sub']['id']  # Extract user ID from decoded data
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired. Please log in again.'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

    # Prepare data from the request body
    verification_data = data

    print(verification_data)

    # Check if HIPAA data exists for this user
    existing_data = Verification.query.filter_by(user_id=user_id).first()
    if existing_data:
        # Update the existing record
        existing_data.applicant_name = verification_data.get('applicantName', existing_data.applicant_name)
        existing_data.phone = verification_data.get('phone', existing_data.phone)
        existing_data.title = verification_data.get('title', existing_data.title)
        existing_data.applicant_signature = verification_data.get('applicantSignature', existing_data.applicant_signature)
        existing_data.applicant_date = verification_data.get('applicantDate', existing_data.applicant_date)
        existing_data.employer = verification_data.get('employer', existing_data.employer)
        existing_data.employer_phone = verification_data.get('employerPhone', existing_data.employer_phone)
        existing_data.address = verification_data.get('address', existing_data.address)
        existing_data.dates_employed_from = verification_data.get('datesEmployedFrom', existing_data.dates_employed_from)
        existing_data.dates_employed_to = verification_data.get('datesEmployedTo', existing_data.dates_employed_to)
        existing_data.employer_dates_from = verification_data.get('employerDatesFrom', existing_data.employer_dates_from)
        existing_data.employer_dates_to = verification_data.get('employerDatesTo', existing_data.employer_dates_to)
        existing_data.position_held = verification_data.get('positionHeld', existing_data.position_held)
        existing_data.quality_of_work = verification_data.get('qualityOfWork', existing_data.quality_of_work)
        existing_data.attendance_punctuality = verification_data.get('attendancePunctuality', existing_data.attendance_punctuality)
        existing_data.problems_noted = verification_data.get('problemsNoted', existing_data.problems_noted)
        existing_data.eligible_for_rehire = verification_data.get('eligibleForRehire', existing_data.eligible_for_rehire)
        existing_data.rehire_explanation = verification_data.get('rehireExplanation', existing_data.rehire_explanation)
        existing_data.employer_signature = verification_data.get('employerSignature', existing_data.employer_signature)
        existing_data.employer_title = verification_data.get('employerTitle', existing_data.employer_title)
        existing_data.employer_date = verification_data.get('employerDate', existing_data.employer_date)
    else:
        # Create a new record
        new_verification_data = Verification(
            user_id=user_id,
            applicant_name=verification_data.get('applicantName'),
            phone=verification_data.get('phone'),
            title=verification_data.get('title'),
            applicant_signature=verification_data.get('applicantSignature'),
            applicant_date=verification_data.get('applicantDate'),
            employer=verification_data.get('employer'),
            employer_phone=verification_data.get('employerPhone'),
            address=verification_data.get('address'),
            dates_employed_from=verification_data.get('datesEmployedFrom'),
            dates_employed_to=verification_data.get('datesEmployedTo'),
            employer_dates_from=verification_data.get('employerDatesFrom'),
            employer_dates_to=verification_data.get('employerDatesTo'),
            position_held=verification_data.get('positionHeld'),
            quality_of_work=verification_data.get('qualityOfWork'),
            attendance_punctuality=verification_data.get('attendancePunctuality'),
            problems_noted=verification_data.get('problemsNoted'),
            eligible_for_rehire=verification_data.get('eligibleForRehire'),
            rehire_explanation=verification_data.get('rehireExplanation'),
            employer_signature=verification_data.get('employerSignature'),
            employer_title=verification_data.get('employerTitle'),
            employer_date=verification_data.get('employerDate')
        )
        db.session.add(new_verification_data)

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": "Verification data saved successfully!"}), 200



@main.route('/get_verification_data', methods=['GET'])
def get_verification_data():
    try:
        # Fetch all employee data records
        verification_data = Verification.query.all()

        # Check if data exists
        if verification_data:
            # Serialize all records into a list of dictionaries
            verification_records = [
                {
                    'id': auth.id,
                    'user_id': auth.user_id,
                    'applicant_name': auth.applicant_name,
                    'phone': auth.phone,
                    'title': auth.title,
                    'applicant_signature': auth.applicant_signature,
                    'applicant_date': auth.applicant_date,
                    'employer': auth.employer,
                    'employer_phone': auth.employer_phone,
                    'address': auth.address,
                    'dates_employed_from': auth.dates_employed_from,
                    'dates_employed_to': auth.dates_employed_to,
                    'employer_dates_from': auth.employer_dates_from,
                    'employer_dates_to': auth.employer_dates_to,
                    'position_held': auth.position_held,
                    'quality_of_work': auth.quality_of_work,
                    'attendance_punctuality': auth.attendance_punctuality,
                    'problems_noted': auth.problems_noted,
                    'eligible_for_rehire': auth.eligible_for_rehire,
                    'rehire_explanation': auth.rehire_explanation,
                    'employer_signature': auth.employer_signature,
                    'employer_title': auth.employer_title,
                    'employer_date': auth.employer_date
                }
                for auth in verification_data
            ]

            # Return the list of serialized records
            return jsonify({'verification_data': verification_records }), 200
        else:
            return jsonify({'message': 'No verification data found'}), 404

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch data'}), 500
    
    
@main.route('/job', methods=['POST'])
def save_job_data():
    # Get data from request
    data = request.get_json()

    # Get the token from the Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    # Decode the token and extract the user_id
    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_data['sub']['id']  # Extract user ID from decoded data
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired. Please log in again.'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

    # Prepare data from the request body
    job_data = data

    # Check if HIPAA data exists for this user
    existing_data = JobAgreement.query.filter_by(user_id=user_id).first()
    if existing_data:
        # Update the existing record with new data
        existing_data.agreed_to = job_data.get('agreedTo', existing_data.agreed_to)
        existing_data.accepted_by = job_data.get('acceptedBy', existing_data.accepted_by)
        existing_data.employee = job_data.get('employee', existing_data.employee)
        existing_data.employment_specialist = job_data.get('employmentSpecialist', existing_data.employment_specialist)
        existing_data.date_1 = job_data.get('date1', existing_data.date_1)
        existing_data.date_2 = job_data.get('date2', existing_data.date_2)
    else:
        # Create a new record if no existing data is found
        new_job_data = JobAgreement(
            user_id=user_id,
            agreed_to=job_data.get('agreedTo'),
            accepted_by=job_data.get('acceptedBy'),
            employee=job_data.get('employee'),
            employment_specialist=job_data.get('employmentSpecialist'),
            date_1=job_data.get('date1'),
            date_2=job_data.get('date2')
        )
        db.session.add(new_job_data)
        db.session.add(new_job_data)

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": "HIPAA data saved successfully!"}), 200


@main.route('/get_job_data', methods=['GET'])
def get_job_data():
    try:
        # Fetch all employee data records
        job_data = JobAgreement.query.all()

        # Check if data exists
        if job_data:
            # Serialize all records into a list of dictionaries
            job_records = [
                {
                    'id': auth.id,
                    'user_id': auth.user_id,
                    'agreed_to': auth.agreed_to,
                    'accepted_by': auth.accepted_by,
                    'employee': auth.employee,
                    'employment_specialist': auth.employment_specialist,
                    'date_1': auth.date_1,
                    'date_2': auth.date_2
                }
                for auth in job_data
            ]

            # Return the list of serialized records
            return jsonify({'job_data': job_records }), 200
        else:
            return jsonify({'message': 'No data found'}), 404

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch data'}), 500
    

@main.route('/nurse', methods=['POST'])
def save_nurse_data():
    # Get data from request
    data = request.get_json()

    # Get the token from the Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    # Decode the token and extract the user_id
    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_data['sub']['id']  # Extract user ID from decoded data
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired. Please log in again.'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

    # Prepare data from the request body
    nurse_data = data

    # Check if HIPAA data exists for this user
    existing_data = NurseAgreement.query.filter_by(user_id=user_id).first()
    if existing_data:
        # Update the existing record with new data
        existing_data.agreed_to = nurse_data.get('agreedTo', existing_data.agreed_to)
        existing_data.accepted_by = nurse_data.get('acceptedBy', existing_data.accepted_by)
        existing_data.employee = nurse_data.get('employee', existing_data.employee)
        existing_data.employment_specialist = nurse_data.get('employmentSpecialist', existing_data.employment_specialist)
        existing_data.date_1 = nurse_data.get('date1', existing_data.date_1)
        existing_data.date_2 = nurse_data.get('date2', existing_data.date_2)
    else:
        # Create a new record if no existing data is found
        new_job_data = NurseAgreement(
            user_id=user_id,
            agreed_to=nurse_data.get('agreedTo'),
            accepted_by=nurse_data.get('acceptedBy'),
            employee=nurse_data.get('employee'),
            employment_specialist=nurse_data.get('employmentSpecialist'),
            date_1=nurse_data.get('date1'),
            date_2=nurse_data.get('date2')
        )
        db.session.add(new_job_data)
        db.session.add(new_job_data)

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": "Data saved successfully!"}), 200


@main.route('/get_nurse_data', methods=['GET'])
def get_nurse_data():
    try:
        # Fetch all employee data records
        nurse_data = NurseAgreement.query.all()

        # Check if data exists
        if nurse_data:
            # Serialize all records into a list of dictionaries
            nurse_records = [
                {
                    'id': auth.id,
                    'user_id': auth.user_id,
                    'agreed_to': auth.agreed_to,
                    'accepted_by': auth.accepted_by,
                    'employee': auth.employee,
                    'employment_specialist': auth.employment_specialist,
                    'date_1': auth.date_1,
                    'date_2': auth.date_2
                }
                for auth in nurse_data
            ]

            # Return the list of serialized records
            return jsonify({'nurse_data': nurse_records }), 200
        else:
            return jsonify({'message': 'No data found'}), 404

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch data'}), 500
    

@main.route('/registered_nurse', methods=['POST'])
def save_registered_nurse_data():
    # Get data from request
    data = request.get_json()

    # Get the token from the Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    # Decode the token and extract the user_id
    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_data['sub']['id']  # Extract user ID from decoded data
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired. Please log in again.'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

    # Prepare data from the request body
    registered_nurse_data = data

    # Check if HIPAA data exists for this user
    existing_data = RegisteredNurseAgreement.query.filter_by(user_id=user_id).first()
    if existing_data:
        # Update the existing record with new data
        existing_data.agreed_to = registered_nurse_data.get('agreedTo', existing_data.agreed_to)
        existing_data.accepted_by = registered_nurse_data.get('acceptedBy', existing_data.accepted_by)
        existing_data.employee = registered_nurse_data.get('employee', existing_data.employee)
        existing_data.employment_specialist = registered_nurse_data.get('employmentSpecialist', existing_data.employment_specialist)
        existing_data.date_1 = registered_nurse_data.get('date1', existing_data.date_1)
        existing_data.date_2 = registered_nurse_data.get('date2', existing_data.date_2)
    else:
        # Create a new record if no existing data is found
        new_job_data = RegisteredNurseAgreement(
            user_id=user_id,
            agreed_to= registered_nurse_data.get('agreedTo'),
            accepted_by= registered_nurse_data.get('acceptedBy'),
            employee= registered_nurse_data.get('employee'),
            employment_specialist= registered_nurse_data.get('employmentSpecialist'),
            date_1= registered_nurse_data.get('date1'),
            date_2= registered_nurse_data.get('date2')
        )
        db.session.add(new_job_data)
        db.session.add(new_job_data)

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": "Data saved successfully!"}), 200


@main.route('/get_registered_nurse_data', methods=['GET'])
def get_registered_nurse_data():
    try:
        # Fetch all employee data records
        registered_nurse_data = RegisteredNurseAgreement.query.all()

        # Check if data exists
        if registered_nurse_data:
            # Serialize all records into a list of dictionaries
            registered_nurse_records = [
                {
                    'id': auth.id,
                    'user_id': auth.user_id,
                    'agreed_to': auth.agreed_to,
                    'accepted_by': auth.accepted_by,
                    'employee': auth.employee,
                    'employment_specialist': auth.employment_specialist,
                    'date_1': auth.date_1,
                    'date_2': auth.date_2
                }
                for auth in registered_nurse_data
            ]

            # Return the list of serialized records
            return jsonify({'registered_nurse_data': registered_nurse_records }), 200
        else:
            return jsonify({'message': 'No data found'}), 404

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch data'}), 500
    

@main.route('/handbook', methods=['POST'])
def save_handbook_data():
    # Get data from request
    data = request.get_json()

    # Get the token from the Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 403
    
    # Decode the token and extract the user_id
    try:
        token = token.split(" ")[1]  # Extract token from 'Bearer <token>'
        decoded_data = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = decoded_data['sub']['id']  # Extract user ID from decoded data
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired. Please log in again.'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token.'}), 403

    # Prepare data from the request body
    handbook_data = data

    # Check if HIPAA data exists for this user
    existing_data = HandBook.query.filter_by(user_id=user_id).first()
    if existing_data:
        # Update the existing record with new data
        existing_data.employee_name = handbook_data.get('employeeName', existing_data.employee_name)
        existing_data.employee_signature = handbook_data.get('employeeSignature', existing_data.employee_signature)
        existing_data.employee_date = handbook_data.get('signatureDate', existing_data.employee_date)
        existing_data.representative_name = handbook_data.get('representativeName', existing_data.representative_name)
        existing_data.representative_date = handbook_data.get('representativeDate', existing_data.representative_date)
        # Add other fields here if applicable
    else:
        # Create a new record if no existing data is found
        new_handbook_data = HandBook(
            user_id=user_id,
            employee_name=handbook_data.get('employeeName'),
            employee_signature=handbook_data.get('employeeSignature'),
            employee_date=handbook_data.get('employeeDate'),
            representative_name=handbook_data.get('representativeName'),
            representative_date=handbook_data.get('representativeDate'),
            # Add other fields here if applicable
        )
        db.session.add(new_handbook_data)

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": "Data saved successfully!"}), 200


@main.route('/get_handbook_data', methods=['GET'])
def get_handbook_data():
    try:
        # Fetch all employee data records
        handbook_data = HandBook.query.all()

     

        # Check if data exists
        if handbook_data:
            # Serialize all records into a list of dictionaries
            handbook_records = [
                {
                    'id': auth.id,
                    'user_id': auth.user_id,
                    'employee_name': auth.employee_name,
                    'employee_signature': auth.employee_signature,
                    'employee_date': auth.employee_date,
                    'representative_name': auth.representative_name,
                    'representative_date': auth.representative_date,
                }
                for auth in handbook_data
            ]

            # Return the list of serialized records
            print(handbook_records)
            return jsonify({'handbook_data': handbook_records }), 200
        else:
            return jsonify({'message': 'No data found'}), 404

    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch data'}), 500


@main.route("/users", methods=["GET"])
def get_users():
    users = User.query.all()
    user_list = [{"username": user.username, "email": user.email} for user in users]
    return jsonify(user_list), 200
