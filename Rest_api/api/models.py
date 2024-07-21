from django.db import models
import uuid
import json
from django.contrib.auth.models import User, AbstractUser, Group, Permission
from django.utils import timezone

TYPE_CHOICES = [
    ("Cloud", "Cloud"),
    ("Infra", "Infra"),
    ("Website", "Website"),
    ("Webapp", "Webapp"),
    ("API", "API"),
    ("Mobile", "Mobile"),
]


class Tenant(models.Model):
    """
    Model representing a tenant.

    Attributes:
        useruuid (ForeignKey): A foreign key reference to the User model representing the tenant's user.
        name (CharField): The name of the tenant, limited to 100 characters and must be unique.
    """
    useruuid = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100, unique=True)

    def __str__(self) -> str:
        return self.name


class UserProfile(models.Model):
    """
    Model representing a user profile.

    Attributes:
        email (EmailField): The email address of the user profile, must be unique.
        useruuid (ForeignKey): A foreign key reference to the User model associated with this profile.
        tenant_uuid (ForeignKey): A foreign key reference to the Tenant model, representing the tenant associated with this profile. It's nullable and blank.
    """
    email = models.EmailField(unique=True)
    useruuid = models.ForeignKey(User, on_delete=models.CASCADE)
    tenant_uuid = models.ForeignKey(
        Tenant, on_delete=models.CASCADE, null=True, blank=True
    )

    def __str__(self) -> str:
        return self.email


class UserOtp(models.Model):
    """
    Model representing a user OTP (One-Time Password).

    Attributes:
        useruuid (ForeignKey): A foreign key reference to the User model associated with this OTP.
        otp (CharField): The OTP value, limited to 6 characters.
        is_active (BooleanField): A boolean indicating whether the OTP is currently active.
        created_at (DateTimeField): The datetime when the OTP was created.
    """
    useruuid = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.otp


class BlacklistedToken(models.Model):
    token = models.CharField(max_length=255, unique=True)
    invalidated_at = models.DateTimeField(auto_now_add=True)


class TenantUser(models.Model):
    """
    Model representing a tenant user.

    Attributes:
        tenant_id (UUIDField): The unique identifier for the tenant user, automatically generated using UUID version 4.
        name (CharField): The name of the tenant user, limited to 100 characters.
        organization_name (CharField): The name of the organization associated with the tenant user, limited to 300 characters.
        is_active (BooleanField): A boolean indicating whether the tenant user is currently active.
    """

    tenant_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(
        max_length=100,
        default="",
    )
    organization_name = models.CharField(max_length=300)
    is_active = models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.name


class Target(models.Model):
    """
    Model representing a target.

    Attributes:
        name (CharField): The name of the target, limited to 300 characters.
        labels (CharField): Labels associated with the target, limited to 300 characters.
        tags (CharField): Tags associated with the target, limited to 300 characters.
        target_notes (CharField): Additional notes or descriptions for the target, limited to 300 characters.
        type (CharField): Type of the target, selected from predefined choices.
        key1 (CharField): First key associated with the target, limited to 300 characters.
        key2 (CharField): Second key associated with the target, limited to 300 characters.
        field1 (CharField): First field associated with the target, limited to 300 characters.
        field2 (CharField): Second field associated with the target, limited to 300 characters.
        deleted (BooleanField): Indicates if the target is marked as deleted.
        deleted_at (DateTimeField): Date and time when the target was marked as deleted. Can be null and blank if the target is not deleted.

    Note:
        - TYPE_CHOICES: A predefined set of choices for the 'type' field needs to be defined elsewhere in the code.
    """
    name = models.CharField(max_length=300)
    labels = models.CharField(max_length=300)
    tags = models.CharField(max_length=300)
    target_notes = models.CharField(max_length=300)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    key1 = models.CharField(max_length=300)
    key2 = models.CharField(max_length=300)
    field1 = models.CharField(max_length=300)
    field2 = models.CharField(max_length=300)
    deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return self.name


class UserCustom(AbstractUser):
    """
    Custom user model representing a user with additional fields.

    Inherits:
        AbstractUser: Django's built-in abstract user model.

    Attributes:
        tenant (ForeignKey): A foreign key reference to the Tenant model representing the user's associated tenant.
        is_active (BooleanField): A boolean indicating whether the user account is active.
        groups (ManyToManyField): Many-to-many relationship with the Group model, allowing a user to belong to multiple groups.
        user_permissions (ManyToManyField): Many-to-many relationship with the Permission model, specifying the permissions granted to the user.

    Note:
        The user's basic information (e.g., username, password) is inherited from the AbstractUser model.
    """
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    groups = models.ManyToManyField(Group, related_name="custom_users")
    user_permissions = models.ManyToManyField(Permission, related_name="custom_users")

    def __str__(self) -> str:
        return self.tenant.name


class Project(models.Model):
    """
    Model representing a project.

    Attributes:
        name (CharField): The name of the project, limited to 100 characters.
        description (TextField): A detailed description of the project.
        retest (BooleanField): Indicates whether the project needs retesting.
        targets (ManyToManyField): Many-to-many relationship with the Target model, representing the targets associated with the project.
        is_deleted (BooleanField): Indicates whether the project is marked as deleted.

    Note:
        - Related name for the 'targets' field is 'project_target'.
    """
    name = models.CharField(max_length=100)
    description = models.TextField()
    retest = models.BooleanField(default=False)
    targets = models.ManyToManyField(Target, related_name="project_target")
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Risk(models.Model):
    """
    Model representing a risk associated with a project.

    Attributes:
        project (ForeignKey): A foreign key reference to the Project model representing the project associated with the risk.
        description (TextField): A detailed description of the risk.

    Note:
        - Related name for the 'project' field is 'projectrisk'.
    """
    project = models.ForeignKey(
        Project, related_name="projectrisk", on_delete=models.CASCADE
    )
    description = models.TextField()

    def __str__(self):
        return self.description


class Vulnerability(models.Model):
    """
    Model representing a vulnerability associated with a project.

    Attributes:
        project (ForeignKey): A foreign key reference to the Project model representing the project associated with the vulnerability.
        description (TextField): A detailed description of the vulnerability.

    Note:
        - Related name for the 'project' field is 'vulnerabilities'.
    """
    project = models.ForeignKey(
        Project, related_name="vulnerabilities", on_delete=models.CASCADE
    )
    description = models.TextField()

    def __str__(self):
        return self.description


class Scan(models.Model):
    """
    Model representing a scan.

    Attributes:
        SCAN_SCHEDULE_CHOICES (tuple): Choices for the scan schedule.
        scan_id (UUIDField): The unique identifier for the scan, automatically generated using UUID version 4.
        targets (ForeignKey): A foreign key reference to the Target model representing the scan's target.
        scan_engines (CharField): The scan engine used for the scan.
        scan_schedule (CharField): The schedule for the scan, selected from predefined choices.
        start_time (DateTimeField): The datetime when the scan starts.
        is_deleted (BooleanField): Indicates whether the scan is marked as deleted.

    Note:
        - TYPE_CHOICES: A predefined set of choices for the 'scan_engines' field needs to be defined elsewhere in the code.
    """
    SCAN_SCHEDULE_CHOICES = (
        ("One time", "One time"),
        ("Daily", "Daily"),
        ("Weekly", "Weekly"),
        ("Monthly", "Monthly"),
        ("Custom", "Custom"),
    )
    scan_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    targets = models.ForeignKey(Target, on_delete=models.CASCADE)
    scan_engines = models.CharField(max_length=10, choices=TYPE_CHOICES)
    scan_schedule = models.CharField(max_length=10, choices=SCAN_SCHEDULE_CHOICES)
    start_time = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.scan_engines


class Risks(models.Model):
    """
        Model representing a risk.

    """
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity_choices = (
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    )
    incoming_severity = models.CharField(max_length=20, choices=severity_choices)
    remediation = models.TextField()
    references = models.TextField()
    poc = models.TextField()
    compliances = models.TextField()
    last_detected = models.DateTimeField()
    user_modified_severity = models.BooleanField(default=False)
    ums = models.DateTimeField(null=True, blank=True)
    ums_notes = models.TextField(blank=True)
    rt_enum = models.CharField(max_length=20)
    rt_notes = models.TextField(blank=True)
    rt_user = models.ForeignKey(User, models.CASCADE)
    rt_datetime = models.DateTimeField(null=True, blank=True)
    project = models.ForeignKey(Project, models.CASCADE)
    scan = models.ForeignKey(Scan, models.CASCADE)
    is_deleted = models.BooleanField(default=False)

    def delete(self, using=None, keep_parents=False):
        self.is_deleted = True
        self.save()

    class Meta:
        ordering = ["-id"]
