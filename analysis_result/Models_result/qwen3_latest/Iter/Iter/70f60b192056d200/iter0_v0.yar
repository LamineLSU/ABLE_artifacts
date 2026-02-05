rule MaliciousBehavior
{
    meta:
        description = "Detects malicious behavior through specific call sequences and control flow patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    strings:
        $pattern0 = { 36 50 FF 15 ?? ?? ?? ?? }
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $pattern2 = { C1 E8 08 A8 01 75 10 }
    condition:
        any of ($pattern0, $pattern1, $pattern2)
}