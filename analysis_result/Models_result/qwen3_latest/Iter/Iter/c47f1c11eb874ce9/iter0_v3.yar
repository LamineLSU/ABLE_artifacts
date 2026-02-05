rule bypass_check1
{
    meta:
        description = "Bypass DEC EAX and JNZ check"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 48 75 ?? 83 38 00 }
    condition:
        $a
}