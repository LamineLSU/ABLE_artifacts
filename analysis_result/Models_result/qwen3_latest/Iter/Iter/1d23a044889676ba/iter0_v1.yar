rule Malware_Evasion_Detection
{
    meta:
        description = "Detects early exit evasion by setting breakpoints on specific call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-05"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? }
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 59 }

    condition:
        any of them
}