#include <emp-tool/emp-tool.h>
#include "emp-agmpc/RecIO.hpp"
#include "emp-agmpc/RepIO.hpp"
#include "emp-agmpc/emp-agmpc.h"
using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
static char out3[] = "92b404e556588ced6c1acd4ebf053f6809f73a93";//bafbc2c87c33322603f38e06c3e0f79c1f1b1475";


 

	/*
	NetIOMP<RepIO,nP> rio(party, port);
	NetIOMP<RepIO,nP> rio2(party, port+2*(nP+1)*(nP+1)+1);
	NetIOMP<RepIO,nP> *rios[2] = {&rio, &rio2};

	for(int i=1;i<=nP;i++){
		if(i==party)continue;
		if(io.ios[i])
			rio.ios[i]->recv_rec=io.ios[i]->recv_rec;
		if(io.ios2[i])
			rio.ios2[i]->recv_rec=io.ios2[i]->recv_rec;

		if(io2.ios[i])
			rio2.ios[i]->recv_rec=io2.ios[i]->recv_rec;
		if(io2.ios2[i])
			rio2.ios2[i]->recv_rec=io2.ios2[i]->recv_rec;
	}
	


	prng.reseed(&seed);
	CMPC<RepIO,nP>* mpc2 = new CMPC<RepIO,nP>(rios, &pool, party, &cf,prng);

	mpc2->function_independent();
	mpc2->function_dependent();
	memset(in, false, 512);	
	mpc2->online(in, out);
	if(party == 1) { 
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << hex_to_binary(string(out3))<<endl;
		cout << res<<endl;
		cout << (res == hex_to_binary(string(out3))? "GOOD!":"BAD!")<<endl<<flush;
	}

*/

const static int nP = 3;
 
void prove_verify(bool *in,int in_len,block seed,NetIOMP<RecIO,nP> *ios[2],int party,int port){
	const int verifier=nP+1;
	NetIOMP<NetIO,nP+1> *io=new NetIOMP<NetIO,nP+1>(party, port+4*(nP+1)*(nP+1)+3);




	if(party<=nP){
		io->send_data(verifier,in,in_len);
		io->send_data(verifier,&seed,sizeof(seed));

		
		// party send to j    ios->get(j,party<j)
		// party recv from j  ios->get(j,j<party) 

		for(int r=0;r<2;r++)
		for(int i=1;i<=nP;i++){
			if(i==party)continue;
			if(ios[r]->ios[i]){
				auto vec=ios[r]->ios[i]->recv_rec;
				int len=vec.size(); 
				io->send_data(verifier,&len,sizeof(len));
				io->send_data(verifier,vec.data(),len);
			}
			if(ios[r]->ios2[i]){
				auto vec=ios[r]->ios2[i]->recv_rec;
				int len=vec.size();  
				io->send_data(verifier,&len,sizeof(len));
				io->send_data(verifier,vec.data(),len);
			}
		}

	}else{
		bool input[512];
		for(int p=2;p<=nP;p++){
			io->recv_data(p,input,512);
			block sed;
			io->recv_data(p,&sed,sizeof(sed));
			PRG prng;prng.reseed(&sed);


			NetIOMP<RepIO,nP> rio(p, port);
			NetIOMP<RepIO,nP> rio2(p, port+2*(nP+1)*(nP+1)+1);
			NetIOMP<RepIO,nP> *rios[2] = {&rio, &rio2};




			for(int r=0;r<2;r++)
			for(int i=1;i<=nP;i++){
				if(i==p)continue;
				if(rios[r]->ios[i]){
					auto &vec=rios[r]->ios[i]->recv_rec;
					int len;
					
					io->recv_data(p,&len,sizeof(len)); 
					vec.resize(len);
					io->recv_data(p,vec.data(),len);
				}
				if(rios[r]->ios2[i]){
					auto &vec=rios[r]->ios2[i]->recv_rec;
					int len; 

					io->recv_data(p,&len,sizeof(len)); 
					vec.resize(len);
					io->recv_data(p,vec.data(),len);
				}
			}
 

			ThreadPool pool(4);	
			string file = circuit_file_location+"/AES-non-expanded.txt";
			file = circuit_file_location+"/sha-1.txt";
			CircuitFile cf(file.c_str()); 

			CMPC<RepIO,nP>* mpc2 = new CMPC<RepIO,nP>(rios, &pool, p, &cf,prng);

 
			mpc2->function_independent();
 
			mpc2->function_dependent(); 

			bool out[160];
			mpc2->online(input, out);
			if(1) { 
				string res = "";
				for(int i = 0; i < cf.n3; ++i)
					res += (out[i]?"1":"0");
				//cout << hex_to_binary(string(out3))<<endl;
				//cout << res<<endl;
				cout << p<<" "<<(res == hex_to_binary(string(out3))? "GOOD!":"BAD!")<<endl<<flush;
			}


		}

	}


}


int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);


	if(party==nP+1){
		prove_verify(0,0,zero_block(),0,party,port);
		return 0;
	}

	NetIOMP<RecIO,nP> io(party, port);
	NetIOMP<RecIO,nP> io2(party, port+2*(nP+1)*(nP+1)+1);
	NetIOMP<RecIO,nP> *ios[2] = {&io, &io2};
	ThreadPool pool(4);	
	string file = circuit_file_location+"/AES-non-expanded.txt";
	file = circuit_file_location+"/sha-1.txt";
	CircuitFile cf(file.c_str());

	PRG prng; block seed=makeBlock(0,0); prng.reseed(&seed);
	CMPC<RecIO,nP>* mpc = new CMPC<RecIO,nP>(ios, &pool, party, &cf,prng);

	mpc->function_independent();
	mpc->function_dependent();
	bool in[512]; bool out[160];
	memset(in, false, 512);	
	mpc->online(in, out);
	if(1) {
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << hex_to_binary(string(out3))<<endl;
		cout << res<<endl;
		cout << (res == hex_to_binary(string(out3))? "GOOD!":"BAD!")<<endl<<flush;
	}




	prove_verify(in,512,seed,ios,party,port);
	

/*	int s=0;
	// party send to j    ios->get(j,party<j)
	// party recv from j  ios->get(j,j<party)
	for(int r=0;r<1;r++)
	for(int j=1;j<=nP;j++){
			if(j==party)continue;
			char dig[128];
			memset(dig,0,sizeof dig);
			
			RecIO *in=ios[r]->get(j,party<j);	
			in->send_hash.digest(dig);
			s=0;
			for(int k=0;k<10;k++)
				s+=dig[k];
			cout<<party<<"->"<<j<<" "<<s<<endl;
			


			in=ios[r]->get(j,j<party);				
			in->recv_hash.digest(dig);
			s=0;
			for(int k=0;k<10;k++)
				s+=dig[k];
			cout<<party<<"<-"<<j<<" "<<s<<endl;

	}
*/

	delete mpc;
	return 0;
}
