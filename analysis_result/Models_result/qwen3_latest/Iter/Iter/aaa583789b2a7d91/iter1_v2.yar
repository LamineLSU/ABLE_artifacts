rule pattern1
{
    meta:
        description = "Push 0 followed by a call to an exit function"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 6A 00 E8 ?? ?? ?? ?? }
    condition:
        $a
}