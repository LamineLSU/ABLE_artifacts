rule SandboxEvasionPatterns
{
    meta:
        description = "Detects sandbox evasion techniques by identifying conditional checks and exit paths in malware execution flow."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 75 07 }
        $pattern1 = { FF 15 ?? ?? ?? ?? 83 F8 11 74 05 }
        $pattern2 = { 85 C9 0B C0 74 2D }

    condition:
        any of them
}