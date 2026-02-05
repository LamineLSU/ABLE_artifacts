rule ExampleRule
{
    meta:
        description = "Matches the observed patterns in the provided code snippet"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { E8 ?? ?? ?? ?? 84 C0 74 11 }
        $b = { FF 15 ?? ?? ?? ?? 48 8B C8 8B D3 }
        $c = { FF 15 3F 18 01 00 }
    condition:
        all of them
}