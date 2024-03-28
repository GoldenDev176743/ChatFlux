from langchain.chains.question_answering import load_qa_chain
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains.qa_with_sources import load_qa_with_sources_chain
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.vectorstores import  Chroma
import docx2txt
import tiktoken
from langchain.docstore.document import Document
from langchain.chains.summarize import load_summarize_chain
from langchain.callbacks import get_openai_callback
from langchain.chains import VectorDBQA
from langchain.chat_models import ChatOpenAI
from langchain.chains import RetrievalQA
import openai
from typing import List, Dict, Any
import re
from typing import List
import numpy as np
from io import StringIO
from io import BytesIO
from pypdf import PdfReader
from openai.error import AuthenticationError
import os
import chardet
import uuid
from langchain.prompts import PromptTemplate
from langchain.retrievers.multi_query import MultiQueryRetriever
from langchain.memory import ConversationBufferMemory
import datetime

embeddings = OpenAIEmbeddings()

def parse_docx(file: BytesIO) -> str:
    text = docx2txt.process(file)
    # Remove multiple newlines
    text = re.sub(r"\n\s*\n", "\n\n", text)
    return text

def parse_pdf(file: BytesIO) -> List[str]:
    print("Parsing PDF...")
    pdf = PdfReader(file)
    output = []
    for i, page in enumerate(pdf.pages):
            try:
                #print(f"Processing page {i+1}")
                text = page.extract_text()
            except Exception as e:
                print(f"Error extracting text from page {i+1}: {e}")
                raise ValueError(f"An error occurred while extracting text from page {i+1}.<br>Please check the PDF for any irregularities such as images, annotations, forms, or unusual text encodings that may interfere with text extraction.<br>If the problem persists, consider trying a different PDF.")
    
            # Merge hyphenated words
            text = re.sub(r"(\w+)-\n(\w+)", r"\1\2", text)
            # Fix newlines in the middle of sentences
            text = re.sub(r"(?<!\n\s)\n(?!\s\n)", " ", text.strip())
            # Remove multiple newlines
            text = re.sub(r"\n\s*\n", "\n\n", text)

            output.append(text)
            
    return output



def parse_txt(file: BytesIO) -> str:
    content = file.read()
    detected_encoding = chardet.detect(content)['encoding']

    text = content.decode(detected_encoding)
    
    # Remove multiple newlines
    text = re.sub(r"\n\s*\n", "\n\n", text)
    return text

def parse_csv(uploaded_file):
    # To read file as bytes:
    #bytes_data = uploaded_file.getvalue()
    #st.write(bytes_data)

    # To convert to a string based IO:
    byte_content = uploaded_file.getvalue()
    detected_encoding = chardet.detect(byte_content)['encoding']
    stringio = StringIO(byte_content.decode(detected_encoding))
    #stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
    #st.write(stringio)

    # To read file as string:
    string_data = stringio.read()
    #st.write(string_data)

    # Can be used wherever a "file-like" object is accepted:
    # dataframe = pd.read_csv(uploaded_file)
    return string_data


def text_to_docsv2(text: str, filename):
    """This new text to docs converts a string or list of strings to a list of Documents 
    and chunks them into pieces, but the new update here is that it adds the filename as metadata"""
    if isinstance(text, str):
        # Take a single string as one page
        text = [text] 

    page_docs = [Document(page_content=page) for page in text]
    #now instead of adding page numbers as metadata, we add the filename
    for i, doc in enumerate(page_docs):
        doc.metadata["filename"] = filename

    # Split pages into chunks
    doc_chunks = []

    # now it will chunk the text into pieces and will keep only the filename as metadata
    for doc in page_docs:
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            separators=["\n\n", "\n", ".", "!", "?", ",", " ", ""],
            chunk_overlap=0,
        )
        chunks = text_splitter.split_text(doc.page_content)

        for i, chunk in enumerate(chunks):
            doc = Document(
                page_content=chunk, metadata={"filename": doc.metadata["filename"]}
            )
            doc_chunks.append(doc)


    return doc_chunks

def text_to_docs(text: str):
    """Converts a string or list of strings to a list of Documents
    with metadata."""
    if isinstance(text, str):
        # Take a single string as one page
        text = [text]

    page_docs = [Document(page_content=page) for page in text]
    # Add page numbers as metadata
    for i, doc in enumerate(page_docs):
        doc.metadata["page"] = i + 1

    # Split pages into chunks
    doc_chunks = []
    
    for doc in page_docs:
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            separators=["\n\n", "\n", ".", "!", "?", ",", " ", ""],
            chunk_overlap=0,
        )
        chunks = text_splitter.split_text(doc.page_content)

        for i, chunk in enumerate(chunks):
            doc = Document(
                page_content=chunk, metadata={"page": doc.metadata["page"], "chunk": i}
            )
            # Add sources a metadata
            doc.metadata["source"] = f"{doc.metadata['page']}-{doc.metadata['chunk']}"
            doc_chunks.append(doc)
    print("lenght of texts list: ", len(doc_chunks))       
    return doc_chunks

def summarize_doc(docx):
    llkm = OpenAI(temperature=0)
    chaiin = load_summarize_chain(llkm, chain_type="map_reduce")
    with get_openai_callback() as cb:
        summary = chaiin.run(docx)
        print(summary)
        cost = cb.total_tokens/1000*0.02
        print(f"tokens used :{cb.total_tokens}, costed : {cost}")
        return summary,cost

from langchain.vectorstores import Chroma, Pinecone
import pinecone
from langchain_pinecone import PineconeVectorStore

def update_docs(docs, chat2update, filename):
    """Embeds a list of Documents and returns a Pinecone index"""
    try:
        #METADATA
        # metadata_for_file = {"filename": filename} 
        #metadatas = [metadata_for_file for _ in docs]

        # for doc in docs:
        #     doc.metadata = metadata_for_file
        # print("First page of the document :")
        # print(docs[0])
        # print("-"*10)
        # print("Last page of the document :")
        # print(docs[-1])
        # print("-"*10)

        chat_id = chat2update
        print(f"Updating ... - Chatbot : {chat_id}")
        #docsearch = Pinecone.from_texts([t.page_content for t in docs], embeddings, index_name="index1", namespace=chat_id, metadatas=metadatas)
        
        # docsearch = Pinecone.from_documents(docs, embeddings, index_name="index1", namespace=chat_id)
        PineconeVectorStore.from_documents(docs, embeddings, index_name="index1", namespace=chat_id)

        print(len(docs))
        #token count
        all_content = ''.join(t.page_content for t in docs)
        encoding = tiktoken.get_encoding("cl100k_base")
        num_tokens = len(encoding.encode(all_content))
        cost = num_tokens/1000*0.0004
        print(f"[Embedding] - tokens used :{num_tokens}, costed : {cost:.6f}")

        return chat_id,cost
    
    except Exception as e:
        print(e)

def embed_docs2(docs, chat_id, filename):
    """Embeds a list of Documents and returns a Pinecone index"""
    try:
        
        # metadata_for_file = {"filename": filename} 
        # #METADATA
        # for doc in docs:
        #     doc.metadata = metadata_for_file

        print(f"Embedding... - Chatbot : {chat_id}")
        # old method wrong docsearch = Pinecone.from_texts([t.page_content for t in docs], embeddings, index_name="index1", namespace=chat_id, metadatas=metadatas)
        
        # for chunk in docs:
        #     # Embed the chunk
        #     print( 
        #         f"Embedding chunk {chunk.metadata['source']} == Lenght : ({len(chunk.page_content)} characters)"
        #     )
        #     docsearch = Pinecone.from_texts([chunk.page_content], embeddings, index_name="index1", namespace=chat_id, metadatas=metadatas)
        
        #new one 
        docsearch = Pinecone.from_documents(docs, embeddings, index_name="index1", namespace=chat_id)
        PineconeVectorStore.from_documents(docs, embeddings, index_name="index1", namespace=chat_id)

        print(len(docs))


        #token count
        all_content = ''.join(t.page_content for t in docs)
        encoding = tiktoken.get_encoding("cl100k_base")
        num_tokens = len(encoding.encode(all_content))
        cost = num_tokens/1000*0.0004
        print(f"[Embedding] - tokens used :{num_tokens}, costed : {cost:.6f}")

        return cost
    
    except Exception as e:
        print(e)


def embed_docs(docs ,docname: str, user_id: str):
    """Embeds a list of Documents and returns a Chromadb index"""
    try:####   REMOVEEE DEBUGGIN PURPRSS
        print("dkhlt")
        doc_id = uuid.uuid4()
        chat_id = f"{user_id}_{doc_id}"
        persist_directory = f"doc/user_{chat_id}_doc_id"
        fold = os.path.join(os.getcwd(), persist_directory)
        if not os.path.exists(fold):
            os.makedirs(fold)
        with get_openai_callback() as cb:
            embeddings = OpenAIEmbeddings() 
            print("db anlacni chromadb")
            all_content = ''.join(doc.page_content for doc in docs)
            encoding = tiktoken.get_encoding("cl100k_base")
            num_tokens = len(encoding.encode(all_content)) 
            db = Chroma.from_documents(docs, embeddings, persist_directory=persist_directory)
            print(f" dumped /{persist_directory}, chat_id : {chat_id}")
            cost = num_tokens/1000*0.0004
            print(f"tokens used :{num_tokens}, costed : {cost}")
            
            
        return chat_id,persist_directory,cost
    except Exception as e:
        print(e)

        
def search_docs(foldname: str):
    folder = "doc/user_"+foldname+"_doc_id"
    folder = os.path.join(os.getcwd(), folder)
    if  os.path.exists(folder):
        print('ok l9ito ',folder)    
    else:
        raise ValueError(f"The doc folder '{folder}' does not exist.")
    return folder


def get_custom_prompt_template(custom_prompt_base):
    # added the chat history to the prompt template in this version
    default_prompt_base = """Your name is "AI Assistant". You will provied me with answers from the given info. If the answer is not included, say "Hmm, I'm not sure this information exists in the content. Maybe try to rephrase the question or clarify your request..." or translate it to the language you got the question in. Don't try to make up an answer."""
    
    prompt_template = f"""{default_prompt_base}
Also, feel free to engage in casual conversation. If greeted with 'hello' or similar phrases, respond in kind to maintain a friendly and interactive experience. Never break character.
Given the following extracted parts of a long document and a question, create a final answer.

{{context}}

#CHAT_HISTORY#
Question: {{question}}
Answer:"""
    
    if custom_prompt_base:
        prompt_template = prompt_template.replace(default_prompt_base, custom_prompt_base)

    custom_prompt_template = PromptTemplate(
        input_variables=["question", "context"], template=prompt_template
    )

    return custom_prompt_template


def moderate(text):
    response = openai.Moderation.create(
        input = text
        )  
    output = response["results"][0]["flagged"]
    return output


# Get answer v4 : Implemented Memory Dict
# Get Answer v4.1 : Implemented Multiple chatbots per session
# Get Answer v4.2 : Implemented Multiple chatbots per session + Database Storage

def get_answer4(chatbot_history, folder, query: str, custom_prompt_base: str = None, use_gpt4: bool = False) -> Dict[str, Any]:
    # Get answer v4.2
    print("==== Get Answer v4.2 =====")

    # Retrieve the conversation history
    history = "\n".join(chatbot_history)

    # Insert the history into the prompt
    custom_prompt_template = get_custom_prompt_template(custom_prompt_base)
    custom_prompt_template.template = custom_prompt_template.template.replace("#CHAT_HISTORY#", history)
   
    # This version uses Multiquery Retrieval + Stuff chain to answer the question
    # docsearch = Pinecone.from_existing_index("index1", embeddings, namespace=folder)
    docsearch = PineconeVectorStore.from_existing_index("index1", embeddings, namespace=folder)
    
    # # Get custom prompt base 
    # custom_prompt_template = get_custom_prompt_template(custom_prompt_base)
    # Check which model to use
    print(f'Using GPT-4 : {use_gpt4}')

    # Completion llm
    llm = ChatOpenAI(
            model_name="gpt-4" if use_gpt4 else "gpt-3.5-turbo",
            temperature=1
        )
    


    with get_openai_callback() as cb: 

        # Multiquery Retrieval
        retriever_from_llm = MultiQueryRetriever.from_llm(
            retriever=docsearch.as_retriever(), 
            llm=llm
        )
        docs = retriever_from_llm.get_relevant_documents(query=query)
        print(f"[OK] Retrieved documents - {len(docs)} docs")
        
        # Now QA Chain
        chain = load_qa_chain(llm=llm, chain_type="stuff", prompt=custom_prompt_template)
        # , verbose=True
        
        output = chain({"input_documents": docs, "question": query}, return_only_outputs=True)
        preanswer = output["output_text"]
        
        # Cost Calculation
        cost = cb.total_tokens/1000*0.02
        print("[QA] - tokens used: ", cb.total_tokens, "cost :", cost)

        # Get time in Y/M/D HH:MM:SS format
        now = datetime.datetime.now()
        now = now.strftime("%Y/%m/%d %H:%M:%S")

        # Answer Moderation
        flagged_answer = moderate(preanswer)
        print(f'[{now}] Answer Moderation result : {flagged_answer} - CID : {folder}')

        if not flagged_answer:
            answer = preanswer
            print(f'[Q] : {query}')
            print(f'[A] : {answer}')
        else:
            answer = "The answer has been flagged by the moderation system."
            print(f'[A] : {answer}')
    
    print("==== End Get Answer =====")
    
    return answer,cost



def get_answer3(folder, query: str, custom_prompt_base: str = None, use_gpt4: bool = False) -> Dict[str, Any]:
    print("get answer v3")
    # This version uses Multiquery Retrieval + Stuff chain to answer the question
    # docsearch = Pinecone.from_existing_index("index1", embeddings, namespace=folder)
    docsearch = PineconeVectorStore.from_existing_index("index1", embeddings, namespace=folder)
    
    # Get custom prompt base 
    custom_prompt_template = get_custom_prompt_template(custom_prompt_base)
    print("-"*10)
    print(f'Prompt template \n: {custom_prompt_template}')
    # Check which model to use
    print(f'Using gpt4 : {use_gpt4}')

    # Completion llm
    llm = ChatOpenAI(
            model_name="gpt-4" if use_gpt4 else "gpt-3.5-turbo",
            temperature=1
        )
    
    # Query Moderation
    flagged_query = moderate(query)
    print("-"*10)
    print(f'Q : {query}')
    print(f'Query Moderation result : {flagged_query} - CID : {folder}')

    if not flagged_query:
        with get_openai_callback() as cb: 

            # Multiquery Retrieval
            retriever_from_llm = MultiQueryRetriever.from_llm(
                retriever=docsearch.as_retriever(), 
                llm=llm
            )
            docs = retriever_from_llm.get_relevant_documents(query=query)
            print(f"Retrieved documents [OK] - {len(docs)} docs")
            # # print all document contents
            # for doc in docs:
            #     print("-"*10)
            #     print(doc.page_content)
            #     print("-"*10)

            # Now QA Chain
            # chain
            chain = load_qa_chain(llm=llm, chain_type="stuff", prompt=custom_prompt_template, verbose=True
            )
            # # old chain
            # chain = load_qa_chain(llm=llm, chain_type="stuff", prompt=custom_prompt_template)
            output = chain({"input_documents": docs, "question": query}, return_only_outputs=True)
            preanswer = output["output_text"]
            
            # Cost Calculation
            cost = cb.total_tokens/1000*0.02
            print("[QA] - tokens used: ", cb.total_tokens, "cost :", cost)

            # Answer Moderation
            flagged_answer = moderate(preanswer)
            print(f'Answer Moderation result : {flagged_answer} - CID : {folder}')
            if not flagged_answer:
                answer = preanswer
                print(f'A : {answer}')
            else:
                answer = "The answer has been flagged by the moderation system."
                print(f'A : {answer}')
            
    else:
        answer = "The query has been flagged by the moderation system."
        print(f'A : {answer}')
    
    print("-"*10)

    return answer,cost

def get_answer2(folder, query: str, custom_prompt_base: str = None, use_gpt4: bool = False) -> Dict[str, Any]:
    
    # docsearch = Pinecone.from_existing_index("index1", embeddings, namespace=folder)
    docsearch = PineconeVectorStore.from_existing_index("index1", embeddings, namespace=folder)
    
    #Processing custom prompt base 
    custom_prompt_template = get_custom_prompt_template(custom_prompt_base)
    chain_type_kwargs = {"prompt": custom_prompt_template}
    print(f'Using gpt4 : {use_gpt4}')
    # completion llm
    llm = ChatOpenAI(
            model_name="gpt-4" if use_gpt4 else "gpt-3.5-turbo",
            temperature=1
        )

    chain = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever= docsearch.as_retriever(),
        chain_type_kwargs=chain_type_kwargs
        # return_source_documents=True
    )

    flagged_query = moderate(query)
    print("-"*10)
    print(f'Q : {query}')
    print(f'Query Moderation result : {flagged_query} - CID : {folder}')

    if not flagged_query:
        with get_openai_callback() as cb: 

            ans = chain({"query": query})
            preanswer = ans["result"]
            #Cost calculation
            cost = cb.total_tokens/1000*0.02
            print("[QA] - tokens used: ", cb.total_tokens, "cost :", cost)

            flagged_answer = moderate(preanswer)
            print(f'Answer Moderation result : {flagged_answer} - CID : {folder}')
            if not flagged_answer:
                answer = preanswer
                print(f'A : {answer}')
            else:
                answer = "The answer has been flagged by the moderation system."
                print(f'A : {answer}')
            
    else:
        answer = "The query has been flagged by the moderation system."
        print(f'A : {answer}')
    
    print("-"*10)

    return answer,cost


def get_answer(afolder, query: str, custom_prompt_base: str = None) -> Dict[str, Any]:

# def get_answer(folder, query: str) -> Dict[str, Any]:
    """Gets an answer to a question from a list of Documents."""
    # Get the answer 
    #####TO CHECK
    folder = f"doc/user_{afolder}_doc_id"
    embeddings = OpenAIEmbeddings()
    db=Chroma(persist_directory=folder, embedding_function=embeddings)
    count = db._collection.count()
    print("loadit db d chroma")

    custom_prompt_template = get_custom_prompt_template(custom_prompt_base)
    chain_type_kwargs = {"prompt": custom_prompt_template}

    #chain_type_kwargs = {"prompt": PROMPT}

    print("ghanbda njawb")
    with get_openai_callback() as cb:
        if count < 4:
            print(f'embeds less than 4 -> :{count}')
            qa = VectorDBQA.from_chain_type(llm=OpenAI(temperature=0.5) , chain_type="stuff", k=count, vectorstore=db, return_source_documents=True, chain_type_kwargs=chain_type_kwargs)
            print(query)
            answer = qa(query)
            # print(answer)
            print("----ANSWER-----")
            print(answer['result'])
            #print("----SOURCES-----")
            #print(answer['source_documents'][page])
            cost = cb.total_tokens/1000*0.02
            print("tokens used: ", cb.total_tokens, "cost :", cost)        
        else:   
            print(f'embeds :{count}')
            qa = VectorDBQA.from_chain_type(llm=OpenAI(temperature=0.5) , chain_type="stuff", vectorstore=db, return_source_documents=True, chain_type_kwargs=chain_type_kwargs)
            print(query)
            answer = qa(query)
            # print(answer)
            print("----ANSWER-----")
            print(answer['result'])
            fans = answer['result']
            #print("----SOURCES-----")
            #print(answer['source_documents'])
            cost = cb.total_tokens/1000*0.02
            print("tokens used: ", cb.total_tokens, "cost :", cost)
            #cost to add to sql 
        
    return fans,cost



def wrap_text_in_html(text: str | List[str]) -> str:
    """Wraps each text block separated by newlines in <p> tags"""
    if isinstance(text, list):
        # Add horizontal rules between pages
        text = "\n<hr/>\n".join(text)
    return "".join([f"<p>{line}</p>" for line in text.split("\n")])


class ChatMemory:
    def __init__(self):
        self.memory = {}

    def add_message(self, user_id, message):
        if user_id not in self.memory:
            self.memory[user_id] = []
        self.memory[user_id].append(message)
        # Limit the history to the last 15 messages
        self.memory[user_id] = self.memory[user_id][-15:]

    def get_history(self, user_id):
        return self.memory.get(user_id, [])

chat_memory = ChatMemory()

# # Usage:
# chat_memory.add_message('user1', 'Hello')
# chat_memory.add_message('user1', 'How are you?')
# print(chat_memory.get_history('user1'))  # ['Hello', 'How are you?']
