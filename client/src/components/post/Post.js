import React, {Fragment, useEffect} from 'react'
import {Link} from 'react-router-dom';
import PropTypes from 'prop-types'
import { connect } from 'react-redux'
import { Spinner } from '../layout/Spinner'
import { getPost }  from '../../actions/post';
import PostItem from '../posts/PostItem';
import CommentForm from './CommentForm';
import CommentItem from '../post/CommentItem';

const Post = ({
    getPost,
    post: {post, loading},
    match
}) => {
    useEffect(() => {
        getPost(match.params.id);
    }, [getPost,match.params.id]);

    return loading || post === null ? <Spinner></Spinner> : <Fragment>
        <Link to='/posts' className='btn' >Back</Link>
        <PostItem post={post} showActions={false}></PostItem>
        <CommentForm postId={post._id} />
        <div className="comments">
            {
                post.comments.map(comment => (
                    <CommentItem key={comment._id} comment={comment} postId={post._id} />
                ))
            }
        </div>
    </Fragment>
}

Post.propTypes = {
    getPost: PropTypes.func.isRequired,
    post: PropTypes.object.isRequired
}

const mapStateToProp = state => ({
    post : state.post
})

export default connect(mapStateToProp,{getPost})(Post);
