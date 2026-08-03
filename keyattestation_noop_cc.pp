import '//releasetools/rapid/workflows/rapid.pp' as rapid

vars = rapid.create_vars() {}

task_deps = [
  'integrate': ['start'],
  'integrate_log': ['integrate'],
]

task_properties = []

workflow create_candidate = rapid.workflow([task_deps, task_properties]) {
  vars = @vars
}
