import '//releasetools/rapid/workflows/rapid.pp' as rapid

vars = rapid.create_vars() {}

artifact_id = vars.process_arguments.get('artifact_id', [''])[0]
auth_token = vars.process_arguments.get('auth_token', [''])[0]
dry_run = vars.process_arguments.get('dry_run', [
                                       true,
                                     ])[0]

task_deps = [
  'gmaven.sign_artifacts': [],
  'gmaven.stage': ['gmaven.sign_artifacts'],
  'gmaven.publish': ['gmaven.stage'],
]

task_properties = [
  'gmaven.sign_artifacts': [
    'gh_artifacts': 'android:keyattestation:' + artifact_id + ':' + auth_token,
    'output_field_name': 'gmaven_signed_zip',
  ],
  'gmaven.stage': [
    'gfile_paths': '%(candidate_custom_field_gmaven_signed_zip)s',
  ],
  'gmaven.publish': [
    'dry_run': dry_run,
  ],
]

workflow keyattestation_release = rapid.workflow([task_deps, task_properties]) {
  vars = @vars
}
