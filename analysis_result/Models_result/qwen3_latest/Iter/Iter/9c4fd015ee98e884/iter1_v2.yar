rule SampleRule
{
    meta:
        description = "Detects specific patterns from a code snippet"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-03-10"

    strings:
        $a = { FF 75 08 E8 C8 FF FF } // push ebp+08, call to ___crtCorExitProcess
        $b = { FF 15 AC B0 41 00 } // call to ExitProcess
        $c = { 8B FF 55 8B EC FF 75 08 } // mov edi, edi; push ebp; mov ebp, esp; push ebp+08

    condition:
        any of ($a, $b, $c)
}