rule Sample_Identifier
{
    meta:
        description = "Identifies a specific code sample based on known byte patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $a = { 6A 00 E8 2D 01 00 00 }  // push 0 followed by call to ExitProcess
        $b = { E8 2D 01 00 00 CC }     // call to ExitProcess followed by int 3
        $c = { 6A 00 E8 2D 00 00 00 CC } // full sequence from push to int 3 (with 0x00 padding)

    condition:
        all of them
}