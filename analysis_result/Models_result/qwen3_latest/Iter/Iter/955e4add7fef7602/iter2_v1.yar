rule TargetCodeSequence
{
    meta:
        description = "Identifies key code sequences from the disassembly"
        cape_options = "bp0=$setup_code+0,action0=skip,bp1=$call_crtcor+0,action1=skip,bp2=$call_exitproc+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-10"
    
    strings:
        $setup_code = { 8B FF 55 8B EC FF 75 08 }
        $call_crtcor = { FF 75 08 E8 C8 FF FF FF }
        $call_exitproc = { FF 75 08 FF 15 AC B0 41 00 }

    condition:
        all of them
}