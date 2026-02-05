rule pattern0
{
    meta:
        description = "Call to ExitProcess with surrounding instructions"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 83 C4 14 52 FF D0 }
    condition:
        $a
}