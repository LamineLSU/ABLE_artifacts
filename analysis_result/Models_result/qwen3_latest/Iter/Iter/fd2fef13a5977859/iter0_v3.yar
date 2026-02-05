rule TestAL01h
{
    meta:
        description = "Matches the test al, 0x01 instruction"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { F6 01 }
    condition:
        $a
}