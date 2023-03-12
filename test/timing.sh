# !bin/sh
# echo 'Testing the time taken'
# for i in {0..100}; do
#    ./safex --policy my_policy.yaml uname -a > temp.txt
#      sleep 0.05
#    ./safex --policy my_policy.yaml mkdir testdir
#     sleep 0.05
#    ./safex --policy my_policy.yaml mv temp.txt pmet.txt
#     sleep 0.05
#    ./safex --policy my_policy.yaml  mv pmet.txt temp.txt
#     sleep 0.05
#    ./safex --policy my_policy.yaml chmod 666 temp.txt
#     sleep 0.05
#    ./safex --policy my_policy.yaml chmod 644 temp.txt
#     sleep 0.05
#    ./safex --policy my_policy.yaml rm temp.txt
#     sleep 0.05
#    ./safex --policy my_policy.yaml rmdir testdir
# done
for i in {0..10}; do
   echo $i
done
