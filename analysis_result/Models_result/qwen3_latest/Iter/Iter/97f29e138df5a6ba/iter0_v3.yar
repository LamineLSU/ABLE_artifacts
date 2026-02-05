rule Malicious_Control_Flow_Bypass
{
    meta:
        description = "Bypasses key control flow points in a malicious binary"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 8B EC E8 CD ?? ?? ?? ?? }
        $b = { C1 E8 08 A8 01 75 ?? }
        $c = { FF 75 08 E8 ?? ?? ?? ?? }
    condition:
        any of them
}