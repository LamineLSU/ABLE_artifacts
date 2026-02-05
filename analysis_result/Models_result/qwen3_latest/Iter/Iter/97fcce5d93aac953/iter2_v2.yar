rule CustomRule
{
    meta:
        description = "Rule targeting specific instruction sequences from the given trace"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 50

    strings:
        $a = { FF 75 08 E8 C8 FF FF FF }
        $b = { 59 FF 75 08 FF 15 F8 10 41 00 }
        $c = { 8B FF 55 8B EC FF 75 08 }

    condition:
        all of them
}