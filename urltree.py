global_url_table ={}


def insert(key,ele):
	global global_url_table
	global_url_table[key] = ele


def re_len():
	global global_url_table
	return len(global_url_table)


def write_file(fp):
	global global_url_table
	for i in global_url_table:
		#fp.write(i+'	'+global_url_table[i] + '\n')
		fp.write('**********\n')
		fp.write(i+'\n')
		fp.write(global_url_table[i]+'\n')
		fp.write('***********\n')


def build_tree(fp):
	global global_url_table
	tree={}
	tree['single_node']=[]
	for i in global_url_table:
		node = global_url_table[i]
		if node == 'empty':
			tree['single_node'].append(i)

		else:
			if not tree.has_key(node):
				tree[node]=[]

			tree[node].append(i)

	fp.write('\n\n\n')
	for i in tree:
		fp.write('-------------------\n')
		fp.write('node :       '+i+'  \n')
		for j in tree[i]:
			fp.write('child :         '+j+'\n')
		fp.write('-------------------\n')

	global_url_table={}







