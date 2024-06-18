import Node1
import time

def main():
	v1 = [1.0, 2.0, 3.0, 4.0]
	v2 = [12.5, 13.5, 14.5, 15.5]
	
	mult_depth = 1
	
	scale_mod_size = 50
	
	batch_size = 8
	
	time.sleep(10)
	
	node1SetupTeple = Node1.encrypt_serialize(v1, v2 , mult_depth, scale_mod_size, batch_size)
