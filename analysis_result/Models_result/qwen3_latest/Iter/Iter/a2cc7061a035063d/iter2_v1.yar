rule FunctionCallPattern
{
    meta:
        description = "Identifies patterns associated with function calls and stack setup"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 E8 C1 FF FF FF }
        $b = { FF 15 5C C2 4C 00 }
        $c = { 55 8B EC FF 75 08 59 }
    condition:
        all of them
}