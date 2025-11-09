ROLE_PERMISSIONS = {
    "applicant": [
        "digitization.view_own",
        "digitization.create_request",
    ],
    "lg_admin": [
        "digitization.view_lg",
        "digitization.approve_request",
        "digitization.export_data",
    ],
    "super_admin": [
        "digitization.view_all",
        "digitization.manage_settings",
    ],
}
