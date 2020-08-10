#include <emp-tool/emp-tool.h>
#include "emp-agmpc/RecIO.hpp"
#include "emp-agmpc/emp-agmpc.h"
using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
static char out3[] = "92b404e556588ced6c1acd4ebf053f6809f73a93";//bafbc2c87c33322603f38e06c3e0f79c1f1b1475";

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	const static int nP = 3;
	NetIOMP<RecIO,nP> io(party, port);
	NetIOMP<RecIO,nP> io2(party, port+2*(nP+1)*(nP+1)+1);
	NetIOMP<RecIO,nP> *ios[2] = {&io, &io2};
	ThreadPool pool(4);	
	string file = circuit_file_location+"/AES-non-expanded.txt";
	file = circuit_file_location+"/sha-1.txt";
	CircuitFile cf(file.c_str());

	PRG prng; block seed=makeBlock(0,0); prng.reseed(&seed);
	CMPC<RecIO,nP>* mpc = new CMPC<RecIO,nP>(ios, &pool, party, &cf,prng);
	cout <<"Setup:\t"<<party<<"\n";

	mpc->function_independent();
	cout <<"FUNC_IND:\t"<<party<<"\n";

	mpc->function_dependent();
	cout <<"FUNC_DEP:\t"<<party<<"\n";

	bool in[512]; bool out[160];
	memset(in, false, 512);
	
	
	mpc->online(in, out);

	int s=0;
	for(int r=0;r<2;r++)
	for(int j=1;j<=nP;j++){
		if(party<j){
			char dig[128];
			memset(dig,0,sizeof dig);
			
			RecIO *in=ios[r]->get(j,false);
			
			if(!in)continue;

			in->send_hash.digest(dig);
			s=0;
			for(int k=0;k<10;k++)
				s+=j*dig[k];
			cout<<party<<" "<<j<<" "<<s<<endl;
		}
	}

	uint64_t band2 = io.count();
	cout <<"bandwidth\t"<<party<<"\t"<<band2<<endl;
	cout <<"ONLINE:\t"<<party<<"\n";
	if(party == 1) {
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << hex_to_binary(string(out3))<<endl;
		cout << res<<endl;
		cout << (res == hex_to_binary(string(out3))? "GOOD!":"BAD!")<<endl<<flush;
	}
	delete mpc;
	return 0;
}
