rule ExitFunctionCall
{
    meta:
        description = "Detects exit function calls or stack setup patterns."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 50

    strings:
        $a = { FF 75 08 FF 15 AC B0 41 00 }  // ExitProcess call with preceding push
        $b = { FF 75 08 E8 C8 FF FF FF }    // CRT exit call with preceding push
        $c = { 55 8B EC FF 75 08 }         // Stack setup (push ebp, mov ebp, push dword [ebp+08h])

    condition:
        any of ($a, $b, $c)
}