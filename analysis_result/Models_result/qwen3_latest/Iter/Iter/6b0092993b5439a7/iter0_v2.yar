rule Pattern1
{
    meta:
        description = "Matches push ebx + call ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 60 E8 ?? ?? ?? ?? }
    condition:
        $a
}