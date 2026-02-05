rule Bypass_Sample
{
    meta:
        description = "Detects potential bypass patterns involving ExitProcess, ShellExecuteW, and CreateMutexA checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2023-10-15"
        license = "BSD (3-clause)"

    strings:
        $pattern0 = { 0F 84 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 F8 20 0F 84 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 85 C0 }

    condition:
        all of them
}