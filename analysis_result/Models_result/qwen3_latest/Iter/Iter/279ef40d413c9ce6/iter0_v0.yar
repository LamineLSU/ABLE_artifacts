rule Malware_Evasion_Checks
{
    meta:
        description = "Detects malware evasion techniques by checking for specific API calls and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-15"

    strings:
        $pattern0 = { 6A 00 FF 15 ?? ?? ?? ?? }
        $pattern1 = { FF 15 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 68 ?? ?? ?? ?? 75 ?? }

    condition:
        any of them
}