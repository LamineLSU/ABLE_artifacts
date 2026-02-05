rule LoopControl
{
    meta:
        description = "Identifies loop control instructions"
        cape_options = "bp0=$loop_control+0,action0=skip,count=0"
    strings:
        $loop_control = { 40 3D 97 00 00 00 75 ?? }
    condition:
        all of them
}