from datetime import datetime
import json
from sqlalchemy import Text
from . import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=True, unique=True)  # Nullable for users, required for admins
    email = db.Column(db.String(120), nullable=True, unique=True)  # Nullable for admins, required for users
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # "user" or "admin"
    category = db.Column(db.String(100), nullable=True)  # Only for users

    def __repr__(self):
        return f"User('{self.username or 'N/A'}', '{self.email or 'N/A'}', '{self.role}')"

    def is_admin(self):
        return self.role == "admin"

    def is_user(self):
        return self.role == "user"
    
   
class ApplyPatient(db.Model):
    __tablename__ = 'apply_patients'  # Name of the table

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    take_over = db.Column(db.String(50), nullable=False, default='Myself')
    gender = db.Column(db.String(10), nullable=False, default='Male')
    age = db.Column(db.String(20), nullable=False, default='Under 18')
    pdn = db.Column(db.String(100), nullable=True)  # Optional field
    pcs = db.Column(db.String(100), nullable=True)  # Optional field
    living_situation = db.Column(db.String(50), nullable=False, default='Living at Home Alone')
    care_plan = db.Column(db.String(50), nullable=False, default='A few hours per week')
    experience = db.Column(db.String(10), nullable=False, default='No')
    paid_status = db.Column(db.String(50), nullable=False, default='Private Funds')
    availability = db.Column(db.String(50), nullable=False, default='Available Now')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<ApplyPatient {self.first_name} {self.last_name}>'

    def to_dict(self):
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "phone": self.phone,
            "take_over": self.take_over,
            "gender": self.gender,
            "age": self.age,
            "pdn": self.pdn,
            "pcs": self.pcs,
            "living_situation": self.living_situation,
            "care_plan": self.care_plan,
            "experience": self.experience,
            "paid_status": self.paid_status,
            "availability": self.availability,
            "created_at": self.created_at.isoformat(),
        }

class StaffApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(255), nullable=True)
    communication = db.Column(db.String(50), nullable=False)
    experience = db.Column(db.Text, nullable=True)
    position = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=True)
    additional_info = db.Column(db.Text, nullable=True)
    is_over_18 = db.Column(db.Boolean, nullable=False)
    is_eligible_to_work = db.Column(db.Boolean, nullable=False)
    ref1_name = db.Column(db.String(100), nullable=True)
    ref1_phone_number = db.Column(db.String(20), nullable=True)
    ref2_name = db.Column(db.String(100), nullable=True)
    ref2_phone_number = db.Column(db.String(20), nullable=True)
    resume_path = db.Column(db.String(255), nullable=True)  # Path to the uploaded resume
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PersonalInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=True)
    ssn = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    number_street = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    state = db.Column(db.String(100), nullable=True)
    zip_code = db.Column(db.String(20), nullable=True)
    referred_by = db.Column(db.String(100), nullable=True)
    salary_desired = db.Column(db.String(50), nullable=True)
    position_category = db.Column(db.String(100), nullable=True)
    shift_desired = db.Column(db.String(50), nullable=True)
    employed = db.Column(db.String(50), nullable=True)
    contact_employer = db.Column(db.String(100), nullable=True)
    
    # Reference to User table
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', backref='personal_info', lazy=True)  # Optional relationship
    
    def __repr__(self):
        return f"PersonalInfo('{self.full_name}', '{self.address}')"


class Education(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(50), nullable=False)
    school = db.Column(db.String(255), nullable=True)
    year = db.Column(db.String(4), nullable=True)
    degree = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign Key

    user = db.relationship('User', backref='educations', lazy=True)  # Optional relationship


class FormerEmployer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_date = db.Column(db.String(10), nullable=True)
    to_date = db.Column(db.String(10), nullable=True)
    employer = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    position = db.Column(db.String(100), nullable=True)
    salary = db.Column(db.String(50), nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign Key

    user = db.relationship('User', backref='former_employers', lazy=True)  # Optional relationship


class PersonalReference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    business = db.Column(db.String(100), nullable=True)
    years_known = db.Column(db.String(2), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign Key

    user = db.relationship('User', backref='personal_references', lazy=True)  # Optional relationship


class ProfessionalKnowledge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    years_of_experience = db.Column(db.String(2), nullable=True)
    specifics = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign Key

    user = db.relationship('User', backref='professional_knowledge', lazy=True)  # Optional relationship



class StaffAuthorization(db.Model):
    __tablename__ = 'staff_authorization'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)  # Foreign key to User table
    first_name = db.Column(db.String(255), nullable=False)
    middle_name = db.Column(db.String(255), nullable=True)
    last_name = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.String(255), nullable=False)  # Changed to VARCHAR
    ssn = db.Column(db.String(255), unique=True, nullable=False)
    drivers_license_number = db.Column(db.String(255), nullable=True)
    state_issued = db.Column(db.String(255), nullable=True)
    former_names = db.Column(db.String(255), nullable=True)
    signature = db.Column(db.String(255), nullable=False)
    signature_date = db.Column(db.String(255), nullable=False)  # Changed to VARCHAR
    created_at = db.Column(db.String(255), default=lambda: datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))  # Changed to VARCHAR


class CriminalBackground(db.Model):
    __tablename__ = 'criminal_background'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)  # Foreign key to User table
    conviction = db.Column(db.String(255), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    employee_signature = db.Column(db.String(255), nullable=False)
    signature_date = db.Column(db.String(255), nullable=False)  # Changed to VARCHAR
    representative_signature = db.Column(db.String(255), nullable=False)
    representative_date = db.Column(db.String(255), nullable=False)  # Changed to VARCHAR
    created_at = db.Column(db.String(255), default=lambda: datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))  # Changed to VARCHAR


class EmployeeData(db.Model):
    __tablename__ = 'employee_data'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, unique=True)
    insurance_company = db.Column(db.String(255), nullable=True)
    claims_representative_phone = db.Column(db.String(50), nullable=True)
    policy_number = db.Column(db.String(100), nullable=True)
    policy_expiration_date = db.Column(db.String(50), nullable=True)
    jd_representative = db.Column(db.String(255), nullable=True)
    coverage_verification_date = db.Column(db.String(50), nullable=True)
    employee_name = db.Column(db.String(255), nullable=True)
    employee_signature = db.Column(db.String(255), nullable=True)
    employee_signature_date = db.Column(db.String(50), nullable=True)
    jd_rep_name = db.Column(db.String(255), nullable=True)
    jd_rep_signature_date = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.String(50), nullable=False, default=datetime.utcnow)

class HipaaData(db.Model):
    __tablename__ = 'hipaa_data'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to User model
    decline_vaccination = db.Column(db.Boolean, default=False)
    employee_signature = db.Column(db.String(200))
    date1 = db.Column(db.String(200))
    hipaa_acknowledgment = db.Column(db.String(200))
    hipaa_signature = db.Column(db.String(200))
    date2 = db.Column(db.String(200))


class Verification(db.Model):
    __tablename__ = 'verification'

    id = db.Column(db.Integer, primary_key=True)  # Primary key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to the User table

    # The rest of the fields as VARCHAR
    applicant_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(255), nullable=True)
    title = db.Column(db.String(255), nullable=True)
    applicant_signature = db.Column(db.String(255), nullable=True)
    applicant_date = db.Column(db.String(255), nullable=True)
    employer = db.Column(db.String(255), nullable=True)
    employer_phone = db.Column(db.String(255), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    dates_employed_from = db.Column(db.String(255), nullable=True)
    dates_employed_to = db.Column(db.String(255), nullable=True)
    employer_dates_from = db.Column(db.String(255), nullable=True)
    employer_dates_to = db.Column(db.String(255), nullable=True)
    position_held = db.Column(db.String(255), nullable=True)
    quality_of_work = db.Column(db.String(255), nullable=True)
    attendance_punctuality = db.Column(db.String(255), nullable=True)
    problems_noted = db.Column(db.String(255), nullable=True)
    eligible_for_rehire = db.Column(db.String(255), nullable=True)
    rehire_explanation = db.Column(db.String(255), nullable=True)
    employer_signature = db.Column(db.String(255), nullable=True)
    employer_title = db.Column(db.String(255), nullable=True)
    employer_date = db.Column(db.String(255), nullable=True)


class JobAgreement(db.Model):
    __tablename__ = 'job_agreements'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Assuming there's a 'users' table
    agreed_to = db.Column(db.String(255))
    accepted_by = db.Column(db.String(255))
    employee = db.Column(db.String(255))
    employment_specialist = db.Column(db.String(255))
    date_1 = db.Column(db.String(200))
    date_2 = db.Column(db.String(200))

class NurseAgreement(db.Model):
    __tablename__ = 'nurse_agreements'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Assuming there's a 'users' table
    agreed_to = db.Column(db.String(255))
    accepted_by = db.Column(db.String(255))
    employee = db.Column(db.String(255))
    employment_specialist = db.Column(db.String(255))
    date_1 = db.Column(db.String(200))
    date_2 = db.Column(db.String(200))

class RegisteredNurseAgreement(db.Model):
    __tablename__ = 'registered_nurse_agreements'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Assuming there's a 'users' table
    agreed_to = db.Column(db.String(255))
    accepted_by = db.Column(db.String(255))
    employee = db.Column(db.String(255))
    employment_specialist = db.Column(db.String(255))
    date_1 = db.Column(db.String(200))
    date_2 = db.Column(db.String(200))


class HandBook(db.Model):
    __tablename__ = 'handbooks'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=False)
    employee_name = db.Column(db.String(150))
    employee_signature = db.Column(db.String(150))
    employee_date = db.Column(db.String(20))  # Date stored as a string
    representative_name = db.Column(db.String(150))
    representative_date = db.Column(db.String(20))