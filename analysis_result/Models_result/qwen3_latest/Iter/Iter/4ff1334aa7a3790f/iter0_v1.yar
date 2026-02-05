rule Detection_Rule
{
    meta:
        description = "Detects specific patterns indicating potential malicious activity"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-05"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 33 C9 E8 ?? ?? ?? ?? }
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }

    condition:
        all of them
}