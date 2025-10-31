killall bf_switchd
killall run_switchd



bf_kdrv_mod_load $SDE_INSTALL

/$SDE/../tools/p4_build.sh vQueues.p4



/$SDE/run_switchd.sh -p vQueues &

sleep 30

#Config PORTS
/$SDE/run_bfshell.sh -f portConfigs 



#Config Tables, Registers etc
/$SDE/run_bfshell.sh -b controlPlane.py 

sleep 10

#Install rules for traffic generation

«



python3 testingTG.py > log &


#Config PORTS
/$SDE/run_bfshell.sh -f portConfigs 




killall bf_switchd
