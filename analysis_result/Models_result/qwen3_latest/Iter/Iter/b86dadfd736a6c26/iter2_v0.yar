rule MaliciousCodeDetection
{
    meta:
        description = "Detects malicious code patterns involving evasion and termination mechanisms"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    strings:
        $pattern0 = { E8 ?? ?? ?? ?? B9 0A 00 00 00 }
        $pattern1 = { EB E9 E8 ?? ?? ?? ?? }
        $pattern2 = { 6A 00 E8 ?? ?? ?? ?? }
    condition:
        any of ($pattern0, $pattern1, $pattern2)
}