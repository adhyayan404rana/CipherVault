"""File-vault graphs from successful file operations or a real benchmark run."""
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st


def record_measurement(history, result, operation):
    if operation not in ('Encryption', 'Decryption'):
        raise ValueError('Unsupported vault operation.')
    row = {'operation':operation, 'size_bytes':result.value['metadata']['size'],
           'key_method':'Key file' if result.value['metadata']['kdf'] == 'RAW-KEY' else 'Password',
           'aes_ms':result.value['aes_seconds']*1000,
           'hash_ms':result.value['hash_seconds']*1000,
           'workflow_ms':result.seconds*1000}
    # Store numeric measurements only; never retain plaintext, passwords or keys here.
    return [*history, row][-100:]


def _figure(title, xlabel, ylabel):
    fig, ax = plt.subplots(figsize=(6,3.3))
    fig.patch.set_facecolor('#121d2d'); ax.set_facecolor('#121d2d')
    ax.set(title=title, xlabel=xlabel, ylabel=ylabel)
    ax.grid(axis='y',alpha=.15)
    return fig, ax


def _show(fig):
    fig.tight_layout(); st.pyplot(fig); plt.close(fig)


def show_operation_graph(result, operation):
    with plt.style.context('dark_background'):
        fig, ax = _figure(operation+' · measured processing time', 'Operation', 'Duration (ms)')
        values = [result.value['aes_seconds']*1000, result.value['hash_seconds']*1000]
        bars = ax.bar(['AES '+operation.lower(),'SHA-256'], values, color=['#38bdf8','#6ee7b7'])
        for bar,value in zip(bars,values):
            ax.annotate(f'{value:.4f} ms',(bar.get_x()+bar.get_width()/2,bar.get_height()),
                        xytext=(0,5),textcoords='offset points',ha='center',fontsize=9)
        ax.margins(y=.25)
        _show(fig)
    st.caption('This file only. Total workflow also includes validation'+(' and password derivation.' if result.value['metadata']['kdf'] != 'RAW-KEY' else '; key-file mode skips password derivation.'))


def show_key_length_graph(duration, failure):
    st.subheader('Password length (characters) vs encryption & decryption time')
    st.caption('Compare 12, 16, 24, 32 and 64 password characters using identical 1 MiB plaintext. Every password derives a 256-bit AES key.')
    if st.button('Run password character-length analysis'):
        import time
        from analysis_service import password_length_analysis
        start = time.perf_counter()
        try:
            with st.spinner('Measuring encryption and decryption for five password lengths…'):
                st.session_state.vault_password_analysis = password_length_analysis()
        except Exception as exc:
            failure(exc,start)
    result = st.session_state.get('vault_password_analysis')
    if result is None:
        st.caption('Run the analysis to generate actual measurements.')
        return
    df = pd.DataFrame(result.value['rows']).sort_values('password_characters')
    with plt.style.context('dark_background'):
        fig,ax = _figure('Password character count vs encryption and decryption time',
                        'Password length (characters)','Median workflow duration (ms)')
        for field,label,color in [('encrypt_ms','Encryption','#38bdf8'),
                                  ('decrypt_ms','Decryption','#6ee7b7')]:
            ax.plot(df.password_characters,df[field],marker='o',color=color,label=label)
        ax.set_xticks(df.password_characters);ax.legend(fontsize=9)
        _show(fig)
    duration('Total password length analysis',result.seconds)
    st.caption('Median of three verified round trips per length. Times include PBKDF2 (600,000 iterations), AES and hashing. Password length does not change AES key size or round count, so timings may remain similar; small fluctuations reflect measurement noise. Character count alone does not determine password strength. CSV separates raw AES and password derivation timings.')
    with st.expander('Password length measurements'):
        st.dataframe(df,hide_index=True,width='stretch')
    st.download_button('Download password length CSV',df.to_csv(index=False),'password-length-timings.csv','text/csv')


def show_vault_comparison(duration, failure, run_benchmarks):
    show_key_length_graph(duration,failure)
    st.subheader('Plaintext size vs encryption & decryption time')
    st.caption('Compare 1 KiB, 10 KiB, 100 KiB, 1 MiB, 5 MiB and 10 MiB plaintexts. Run the size benchmark to measure both operations for every size.')
    if st.button('Run File vault size benchmark'):
        import time
        start = time.perf_counter()
        try:
            with st.spinner('Measuring encryption and decryption across six file sizes…'):
                st.session_state.benchmarks = run_benchmarks()
                st.session_state.vault_graph_source = 'Size benchmark'
        except Exception as exc:
            failure(exc,start)
    history = st.session_state.get('vault_measurements', [])
    benchmark = st.session_state.get('benchmarks')
    sources = (['Your file operations'] if history else []) + (['Size benchmark'] if benchmark else [])
    if not sources:
        st.caption('Encrypt/decrypt files to plot your measured timings, or run the size benchmark above.')
        return
    source = st.selectbox('Graph data',sources,index=len(sources)-1,key='vault_graph_source') if len(sources)>1 else sources[0]
    st.caption('Source · '+source)
    with plt.style.context('dark_background'):
        if source == 'Your file operations':
            df = pd.DataFrame(history)
            if 'key_method' not in df:
                df['key_method'] = 'Password'
            else:
                df['key_method'] = df.key_method.fillna('Password')
            df['size_KiB'] = df.size_bytes/1024
            for column,field,title in zip(st.columns(2), ['aes_ms','workflow_ms'],
                                         ['AES time vs file size','Complete workflow time vs file size']):
                with column:
                    fig, ax = _figure(title,'Original file size (KiB)','Duration (ms)')
                    groups = [('Encryption','Password','#38bdf8','o'),('Decryption','Password','#6ee7b7','o'),
                              ('Encryption','Key file','#c4b5fd','s'),('Decryption','Key file','#fbbf24','s')]
                    for operation,method,color,marker in groups:
                        rows = df[(df.operation == operation) & (df.key_method == method)]
                        if not rows.empty:
                            label = operation+' · '+method
                            ax.scatter(rows.size_KiB,rows[field],color=color,marker=marker,label=label)
                            median = rows.groupby('size_KiB')[field].median().sort_index()
                            if len(median)>1:
                                ax.plot(median.index,median.values,color=color,alpha=.6)
                    ax.legend(fontsize=8);_show(fig)
            st.caption('Saved successful operations (latest 100), grouped by password/key-file mode. Both use 256-bit AES keys. Password mode includes PBKDF2; key-file mode skips it. Compare raw AES separately from the complete workflow.')
        else:
            df = pd.DataFrame(benchmark['rows'])
            for column,field,title,color in zip(st.columns(2),['aes_encrypt_ms','aes_decrypt_ms'],
                ['Encryption time vs plaintext size','Decryption time vs plaintext size'],['#38bdf8','#6ee7b7']):
                with column:
                    fig,ax = _figure(title,'Plaintext size (KiB, logarithmic scale)','Median AES duration (ms)')
                    ax.plot(df.size_KiB,df[field],marker='o',color=color,label='AES-256-GCM')
                    ax.set_xscale('log');ax.legend(fontsize=8);_show(fig)
            duration('Total benchmark run',benchmark['total_seconds'])
            duration('RSA key setup in shared benchmark',benchmark['key_generation_seconds'])
            st.caption('Actual benchmark medians over three trials per size. AES curves exclude password derivation and setup. Larger plaintext generally requires more processing; timing noise affects individual measurements.')
        with st.expander('Graph measurements'):
            st.dataframe(df,hide_index=True,width='stretch')
        st.download_button('Download File vault timings CSV',df.to_csv(index=False),'file-vault-timings.csv','text/csv')
