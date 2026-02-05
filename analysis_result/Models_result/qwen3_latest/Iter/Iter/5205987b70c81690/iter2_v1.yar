rule ExitProcessCall
{
    meta:
        description = "Detects the call to ExitProcess in a Windows process"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 FF 15 AC B0 41 00 }  // push [ebp+08h], call [0x41B0AC]
        $b = { FF 75 08 E8 C8 FF FF FF }       // push [ebp+08h], call [0xFFF8C8]
        $c = { 55 8B EC FF 75 08 }            // push ebp, mov ebp, esp, push [ebp+08h]
    condition:
        all of them
}