@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Interactive runbook: coloured console output for the admin is the point.
        'PSAvoidUsingWriteHost',
        # Case folder and patterns are shared between dot-sourced files in one session on purpose.
        'PSAvoidGlobalVars',
        # Names like Get-BecSignIns / Get-BecDeletedItems describe what is returned.
        'PSUseSingularNouns'
    )
}
