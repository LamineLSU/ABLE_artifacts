rule PushCallSequence
{
    meta:
        description = "A sequence of push ebx followed by a call instruction"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 50 E8 ?? ?? ?? ?? }
    condition:
        $a
}