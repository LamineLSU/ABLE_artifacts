rule MaliciousPattern
{
    meta:
        description = "Detects suspicious patterns involving indirect calls and memory operations"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 53 FF 15 ?? ?? ?? ?? }
        $b = { 83 7D 04 00 FF 15 ?? ?? ?? ?? }
        $c = { 83 7D 08 00 E8 ?? ?? ?? ?? }
    condition:
        any of them
}