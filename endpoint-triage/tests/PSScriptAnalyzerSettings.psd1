@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Runner and setup scripts print progress for the operator on purpose.
        'PSAvoidUsingWriteHost',
        # Names like Get-AccountsAndSessions describe what is returned.
        'PSUseSingularNouns'
    )
    Rules        = @{
        # The checks run on the endpoint under Windows PowerShell 5.1, which is all a stock Windows has.
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
