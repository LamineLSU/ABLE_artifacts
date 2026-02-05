rule Pattern1
{
    meta:
        description = "Indirect call to a target function with conditional jump"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }
    condition:
        $a
}