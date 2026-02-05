rule ExampleRule
{
    meta:
        description = "Matches a specific sequence of instructions from the provided trace."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { E8 25 05 00 00 85 C0 0F 84 ?? ?? ?? ?? }
        $b = { FF 15 2C A1 95 00 }
        $c = { 6A 5B 5A 8B CE E8 25 05 00 00 }
    condition:
        all of them
}