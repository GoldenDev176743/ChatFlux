import pandas as pd
import numpy as np
import pytube
from pytube import YouTube
from langchain.document_loaders import YoutubeLoader
from youtube_transcript_api import YouTubeTranscriptApi
from pytube import extract


def youtubefy(id):
    msg=''
    try:
        #url = input("Youtube link: ")
        #id=extract.video_id(id)
        # retrieve the available transcripts
        transcript_list = YouTubeTranscriptApi.list_transcripts(id)
        # iterate over all available transcripts
        for transcript in transcript_list:
            lang = transcript.language_code
        vidurl = 'https://www.youtube.com/watch?v='+id
        try:
            loader = YoutubeLoader.from_youtube_url(vidurl, language=lang)
            documents = loader.load()
        except Exception as e:
            msg = f'An error occurred while accessing {vidurl}. Please try again. If the error persists, please contact support.'
            print(msg)

        docs = documents[0].page_content
        meta = documents[0].metadata
        # print(docs)
        # print("-----")
        # print(meta)
        
        # title = documents[0].metadata['title']
        # del documents[0].metadata['publish_date']
        # del documents[0].metadata['description']
        # del documents[0].metadata['thumbnail_url']
        # docz = text_to_docs(docs)
        # for d in docz:
        #     d.metadata.update(meta)
    
    except Exception as e:
        if 'Subtitles are disabled for this video' in str(e):
            msg= f'Subtitles are disabled for this video {id}'
        else:
            msg='An error occured. If the error persist, please contact support.'
            print(f'Error: {e}')

    return docs,meta,msg

